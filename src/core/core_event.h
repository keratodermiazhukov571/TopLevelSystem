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
 * core_event.h — Cross-platform event loop (libev wrapper) with timers and signals
 *
 * Scale-ready design:
 *   - Heap-allocated entries array (default 16384 slots, configurable)
 *   - Free-list reuse of freed slots (no slot leak on add/del churn)
 *   - O(1) fd → entry lookup via hashtable (no linear scan)
 *   - portal_event_modify() to change events without del+add churn
 */

#ifndef CORE_EVENT_H
#define CORE_EVENT_H

#include <stdint.h>
#include "portal/core.h"
#include "core_hashtable.h"
#include "ev_config.h"
#include "ev.h"

#define EVENT_MAX_FDS    16384   /* was 256 — scales to 1000+ federated peers */
#define EVENT_MAX_TIMERS 64      /* was 32 — mod_node adds reconnect + sweep timers */

/* Wrapper around ev_io + our callback info */
typedef struct {
    ev_io          watcher;
    portal_fd_fn   callback;
    void          *userdata;
    int            active;
} event_entry_t;

/* Timer callback */
typedef void (*portal_timer_fn)(void *userdata);

typedef struct {
    ev_timer         watcher;
    portal_timer_fn  callback;
    void            *userdata;
    int              active;
} timer_entry_t;

/* SIGHUP callback */
typedef void (*portal_sighup_fn)(void *userdata);

typedef struct {
    struct ev_loop  *loop;
    event_entry_t   *entries;        /* heap-allocated, size = entry_cap */
    int              entry_cap;      /* allocated capacity (EVENT_MAX_FDS) */
    int              entry_high;     /* highest slot index ever used */
    int             *free_list;      /* stack of freed slot indices */
    int              free_count;     /* number of entries on the free list */
    portal_ht_t      fd_to_idx;      /* fd (as string) → int* (slot index) */
    timer_entry_t    timers[EVENT_MAX_TIMERS];
    int              timer_count;
    ev_signal        sig_int;
    ev_signal        sig_term;
    ev_signal        sig_hup;
    portal_sighup_fn sighup_cb;
    void            *sighup_data;
} portal_event_loop_t;

int  portal_event_init(portal_event_loop_t *loop);
void portal_event_destroy(portal_event_loop_t *loop);

int  portal_event_add(portal_event_loop_t *loop, int fd, uint32_t events,
                       portal_fd_fn callback, void *userdata);
int  portal_event_del(portal_event_loop_t *loop, int fd);

/* Modify the event mask on an already-registered fd without a del+add
 * cycle. Returns 0 on success, -1 if fd is not registered. Use this to
 * switch between EV_READ and EV_WRITE (e.g., when a TX buffer drains). */
int  portal_event_modify(portal_event_loop_t *loop, int fd, uint32_t events);

/* Add a repeating timer (interval in seconds) */
int  portal_event_add_timer(portal_event_loop_t *loop, double interval,
                             portal_timer_fn callback, void *userdata);

/* Set SIGHUP handler */
void portal_event_set_sighup(portal_event_loop_t *loop,
                              portal_sighup_fn callback, void *userdata);

int  portal_event_run(portal_event_loop_t *loop);
void portal_event_stop(portal_event_loop_t *loop);

#endif /* CORE_EVENT_H */
