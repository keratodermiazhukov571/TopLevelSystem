/*
 * Author: Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/*
 * core_event.c — Cross-platform event loop (libev wrapper)
 *
 * Wraps embedded libev for fd watching, timers, and signals.
 * Backends: epoll (Linux), kqueue (macOS/BSD), select (Windows).
 * Modules register fds via core->fd_add() for async I/O.
 *
 * Scale-ready design (16384 fd slots by default):
 *   - Heap-allocated entries array
 *   - Free-list reuse of freed slots — no slot leak on add/del churn
 *   - O(1) fd → entry lookup via core_hashtable
 *   - portal_event_modify() changes events in place (no del+add)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "core_event.h"
#include "core_log.h"
#include "portal/constants.h"

/* libev callback → portal callback bridge */
static void ev_io_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    (void)loop;
    event_entry_t *entry = (event_entry_t *)w;
    if (entry->callback)
        entry->callback(w->fd, (uint32_t)revents, entry->userdata);
}

/* Signal handler — stop the loop */
static void ev_signal_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
    (void)w;
    (void)revents;
    LOG_INFO("event", "Signal received, stopping event loop");
    ev_break(loop, EVBREAK_ALL);
}

/* SIGHUP handler */
static void ev_sighup_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
    (void)loop;
    (void)revents;
    /* Find the event loop struct from the watcher */
    portal_event_loop_t *evloop = (portal_event_loop_t *)
        ((char *)w - offsetof(portal_event_loop_t, sig_hup));
    LOG_INFO("event", "SIGHUP received");
    if (evloop->sighup_cb)
        evloop->sighup_cb(evloop->sighup_data);
}

/* Timer callback bridge */
static void ev_timer_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
    (void)loop;
    (void)revents;
    timer_entry_t *entry = (timer_entry_t *)w;
    if (entry->callback)
        entry->callback(entry->userdata);
}

int portal_event_init(portal_event_loop_t *loop)
{
    memset(loop, 0, sizeof(*loop));

    loop->loop = ev_loop_new(EVFLAG_AUTO);
    if (!loop->loop) {
        LOG_ERROR("event", "Failed to create event loop");
        return -1;
    }

    /* Heap-allocate the fd entries array and the free list */
    loop->entry_cap = EVENT_MAX_FDS;
    loop->entries = calloc((size_t)loop->entry_cap, sizeof(event_entry_t));
    loop->free_list = calloc((size_t)loop->entry_cap, sizeof(int));
    if (!loop->entries || !loop->free_list) {
        LOG_ERROR("event", "Failed to allocate fd entry tables (cap=%d)", loop->entry_cap);
        free(loop->entries); loop->entries = NULL;
        free(loop->free_list); loop->free_list = NULL;
        ev_loop_destroy(loop->loop);
        loop->loop = NULL;
        return -1;
    }
    loop->entry_high = 0;
    loop->free_count = 0;

    /* Initialize fd → slot index hashtable */
    portal_ht_init(&loop->fd_to_idx, 512);

#ifndef _WIN32
    ev_signal_init(&loop->sig_int, ev_signal_cb, SIGINT);
    ev_signal_start(loop->loop, &loop->sig_int);

    ev_signal_init(&loop->sig_term, ev_signal_cb, SIGTERM);
    ev_signal_start(loop->loop, &loop->sig_term);

    ev_signal_init(&loop->sig_hup, ev_sighup_cb, SIGHUP);
    ev_signal_start(loop->loop, &loop->sig_hup);
#endif

    const char *backend = "unknown";
    unsigned int b = ev_backend(loop->loop);
    if (b & EVBACKEND_EPOLL)        backend = "epoll";
    else if (b & EVBACKEND_KQUEUE)  backend = "kqueue";
    else if (b & EVBACKEND_POLL)    backend = "poll";
    else if (b & EVBACKEND_SELECT)  backend = "select";

    LOG_INFO("event", "Event loop initialized (backend: %s, fd_cap: %d)",
             backend, loop->entry_cap);
    return 0;
}

void portal_event_destroy(portal_event_loop_t *loop)
{
    if (!loop->loop) return;

    for (int i = 0; i < loop->entry_high; i++) {
        if (loop->entries[i].active) {
            ev_io_stop(loop->loop, &loop->entries[i].watcher);
            loop->entries[i].active = 0;
        }
    }

    for (int i = 0; i < loop->timer_count; i++) {
        if (loop->timers[i].active) {
            ev_timer_stop(loop->loop, &loop->timers[i].watcher);
            loop->timers[i].active = 0;
        }
    }

#ifndef _WIN32
    ev_signal_stop(loop->loop, &loop->sig_int);
    ev_signal_stop(loop->loop, &loop->sig_term);
    ev_signal_stop(loop->loop, &loop->sig_hup);
#endif

    /* Free the fd → idx hashtable values (heap-allocated int boxes) */
    for (size_t i = 0; i < loop->fd_to_idx.capacity; i++) {
        if (loop->fd_to_idx.entries[i].occupied == 1)
            free(loop->fd_to_idx.entries[i].value);
    }
    portal_ht_destroy(&loop->fd_to_idx);

    free(loop->entries);
    loop->entries = NULL;
    free(loop->free_list);
    loop->free_list = NULL;

    ev_loop_destroy(loop->loop);
    loop->loop = NULL;
}

/* Allocate a slot index: prefer recycled slots, fall back to growing high-water */
static int slot_alloc(portal_event_loop_t *loop)
{
    if (loop->free_count > 0)
        return loop->free_list[--loop->free_count];
    if (loop->entry_high < loop->entry_cap)
        return loop->entry_high++;
    return -1;
}

static void slot_free(portal_event_loop_t *loop, int idx)
{
    loop->free_list[loop->free_count++] = idx;
}

static int fd_key(int fd, char *buf, size_t buflen)
{
    return snprintf(buf, buflen, "%d", fd);
}

static int fd_idx_lookup(portal_event_loop_t *loop, int fd)
{
    char key[16];
    fd_key(fd, key, sizeof(key));
    int *box = portal_ht_get(&loop->fd_to_idx, key);
    return box ? *box : -1;
}

int portal_event_add(portal_event_loop_t *loop, int fd, uint32_t events,
                      portal_fd_fn callback, void *userdata)
{
    /* Guard against double-add — caller error, but safe to detect */
    if (fd_idx_lookup(loop, fd) >= 0) {
        LOG_WARN("event", "fd=%d already registered — ignoring duplicate add", fd);
        return -1;
    }

    int idx = slot_alloc(loop);
    if (idx < 0) {
        LOG_ERROR("event", "No free fd slots (cap=%d, high=%d, free=%d)",
                  loop->entry_cap, loop->entry_high, loop->free_count);
        return -1;
    }

    int ev_events = 0;
    if (events & EV_READ)  ev_events |= EV_READ;
    if (events & EV_WRITE) ev_events |= EV_WRITE;
    if (!ev_events) ev_events = EV_READ;

    event_entry_t *entry = &loop->entries[idx];
    memset(entry, 0, sizeof(*entry));
    entry->callback = callback;
    entry->userdata = userdata;
    entry->active = 1;

    ev_io_init(&entry->watcher, ev_io_cb, fd, ev_events);
    ev_io_start(loop->loop, &entry->watcher);

    /* Record fd → idx mapping (value is a heap int so the hashtable can own it) */
    char key[16];
    fd_key(fd, key, sizeof(key));
    int *idx_box = malloc(sizeof(int));
    if (!idx_box) {
        ev_io_stop(loop->loop, &entry->watcher);
        entry->active = 0;
        slot_free(loop, idx);
        return -1;
    }
    *idx_box = idx;
    portal_ht_set(&loop->fd_to_idx, key, idx_box);

    LOG_TRACE("event", "Added fd=%d (slot=%d) to event loop", fd, idx);
    return 0;
}

int portal_event_del(portal_event_loop_t *loop, int fd)
{
    char key[16];
    fd_key(fd, key, sizeof(key));
    int *idx_box = portal_ht_get(&loop->fd_to_idx, key);
    if (!idx_box) return -1;
    int idx = *idx_box;

    event_entry_t *entry = &loop->entries[idx];
    ev_io_stop(loop->loop, &entry->watcher);
    entry->active = 0;
    entry->callback = NULL;
    entry->userdata = NULL;

    /* Return slot to free list for reuse */
    slot_free(loop, idx);

    portal_ht_del(&loop->fd_to_idx, key);
    free(idx_box);

    LOG_TRACE("event", "Removed fd=%d (slot=%d) from event loop", fd, idx);
    return 0;
}

int portal_event_modify(portal_event_loop_t *loop, int fd, uint32_t events)
{
    int idx = fd_idx_lookup(loop, fd);
    if (idx < 0) return -1;

    event_entry_t *entry = &loop->entries[idx];
    if (!entry->active) return -1;

    int ev_events = 0;
    if (events & EV_READ)  ev_events |= EV_READ;
    if (events & EV_WRITE) ev_events |= EV_WRITE;
    if (!ev_events) ev_events = EV_READ;

    /* libev does not expose ev_io_modify that can add/remove events while
     * running — standard pattern is stop, ev_io_set, start. This keeps the
     * same entry slot and the same ev_io watcher struct. */
    ev_io_stop(loop->loop, &entry->watcher);
    ev_io_set(&entry->watcher, fd, ev_events);
    ev_io_start(loop->loop, &entry->watcher);

    return 0;
}

int portal_event_add_timer(portal_event_loop_t *loop, double interval,
                            portal_timer_fn callback, void *userdata)
{
    if (loop->timer_count >= EVENT_MAX_TIMERS)
        return -1;

    timer_entry_t *entry = &loop->timers[loop->timer_count++];
    entry->callback = callback;
    entry->userdata = userdata;
    entry->active = 1;

    ev_timer_init(&entry->watcher, ev_timer_cb, interval, interval);
    ev_timer_start(loop->loop, &entry->watcher);

    LOG_DEBUG("event", "Added timer (interval: %.0fs)", interval);
    return 0;
}

void portal_event_set_sighup(portal_event_loop_t *loop,
                              portal_sighup_fn callback, void *userdata)
{
    loop->sighup_cb = callback;
    loop->sighup_data = userdata;
}

int portal_event_run(portal_event_loop_t *loop)
{
    LOG_DEBUG("event", "Event loop started");
    ev_run(loop->loop, 0);
    LOG_DEBUG("event", "Event loop stopped");
    return 0;
}

void portal_event_stop(portal_event_loop_t *loop)
{
    if (loop->loop)
        ev_break(loop->loop, EVBREAK_ALL);
}
