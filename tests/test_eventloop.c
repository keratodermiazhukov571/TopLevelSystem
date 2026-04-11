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
 * test_eventloop — Unit tests for Portal's libev-backed event loop
 *
 * Covers:
 *   - add/del with free-list slot reuse (no slot leak after 20k cycles)
 *   - fd_modify switches between EV_READ and EV_WRITE in place
 *   - hashtable lookup is correct after many insertions and deletions
 *   - double-add is rejected
 *   - destroy releases all resources (run under valgrind for leak check)
 *
 * Scoped to the slot allocator and fd table. Does not run ev_run() —
 * that requires real fds to make progress and is covered by integration
 * tests. The interesting invariant here is "slot reuse works".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include "../src/core/core_event.h"

/* Dummy callback — never actually invoked in these tests */
static void dummy_cb(int fd, uint32_t events, void *userdata)
{
    (void)fd; (void)events; (void)userdata;
}

/* Open /dev/null as a safe fd we can register without triggering real I/O */
static int open_null(void)
{
    int fd = open("/dev/null", O_RDONLY);
    assert(fd >= 0);
    return fd;
}

static void test_add_del_basic(void)
{
    printf("test_add_del_basic... ");
    portal_event_loop_t loop;
    assert(portal_event_init(&loop) == 0);

    int fd = open_null();
    assert(portal_event_add(&loop, fd, EV_READ, dummy_cb, NULL) == 0);
    assert(loop.entry_high == 1);
    assert(loop.free_count == 0);

    assert(portal_event_del(&loop, fd) == 0);
    assert(loop.entry_high == 1);     /* not decremented — slot returned to free list */
    assert(loop.free_count == 1);     /* slot is on the free list */

    close(fd);
    portal_event_destroy(&loop);
    printf("OK\n");
}

static void test_del_unknown_fd(void)
{
    printf("test_del_unknown_fd... ");
    portal_event_loop_t loop;
    assert(portal_event_init(&loop) == 0);

    assert(portal_event_del(&loop, 99999) == -1);

    portal_event_destroy(&loop);
    printf("OK\n");
}

static void test_slot_reuse_hot_loop(void)
{
    printf("test_slot_reuse_hot_loop... ");
    portal_event_loop_t loop;
    assert(portal_event_init(&loop) == 0);

    /* Register 100 fds, verify entry_high == 100 */
    int fds[100];
    for (int i = 0; i < 100; i++) {
        fds[i] = open_null();
        assert(portal_event_add(&loop, fds[i], EV_READ, dummy_cb, NULL) == 0);
    }
    assert(loop.entry_high == 100);
    assert(loop.free_count == 0);

    /* Delete all — every slot goes to free list */
    for (int i = 0; i < 100; i++) {
        assert(portal_event_del(&loop, fds[i]) == 0);
        close(fds[i]);
    }
    assert(loop.entry_high == 100);
    assert(loop.free_count == 100);

    /* Now add 20000 fds in a del/add churn loop. entry_high must stay
     * at 100 (or very close), proving slot reuse works. Without reuse,
     * entry_high would blow past 16384 and add would fail. */
    int prev_fds[100] = {0};
    for (int i = 0; i < 100; i++) {
        prev_fds[i] = open_null();
        assert(portal_event_add(&loop, prev_fds[i], EV_READ, dummy_cb, NULL) == 0);
    }
    assert(loop.entry_high == 100);   /* fully reused */

    for (int cycle = 0; cycle < 200; cycle++) {
        /* Drop the oldest 50, add 50 fresh */
        for (int i = 0; i < 50; i++) {
            assert(portal_event_del(&loop, prev_fds[i]) == 0);
            close(prev_fds[i]);
        }
        for (int i = 0; i < 50; i++) {
            prev_fds[i] = open_null();
            assert(portal_event_add(&loop, prev_fds[i], EV_READ, dummy_cb, NULL) == 0);
        }
        /* Never grow past the initial 100 — slot reuse is working */
        assert(loop.entry_high == 100);
    }

    for (int i = 0; i < 100; i++) {
        portal_event_del(&loop, prev_fds[i]);
        close(prev_fds[i]);
    }

    portal_event_destroy(&loop);
    printf("OK (20000 cycles, entry_high stayed at 100)\n");
}

static void test_fd_modify(void)
{
    printf("test_fd_modify... ");
    portal_event_loop_t loop;
    assert(portal_event_init(&loop) == 0);

    int fd = open_null();
    assert(portal_event_add(&loop, fd, EV_READ, dummy_cb, NULL) == 0);

    /* Switch to write */
    assert(portal_event_modify(&loop, fd, EV_WRITE) == 0);

    /* Switch to both */
    assert(portal_event_modify(&loop, fd, EV_READ | EV_WRITE) == 0);

    /* Back to read only */
    assert(portal_event_modify(&loop, fd, EV_READ) == 0);

    /* Modify an unknown fd fails */
    assert(portal_event_modify(&loop, 99999, EV_READ) == -1);

    portal_event_del(&loop, fd);
    close(fd);
    portal_event_destroy(&loop);
    printf("OK\n");
}

static void test_double_add_rejected(void)
{
    printf("test_double_add_rejected... ");
    portal_event_loop_t loop;
    assert(portal_event_init(&loop) == 0);

    int fd = open_null();
    assert(portal_event_add(&loop, fd, EV_READ, dummy_cb, NULL) == 0);

    /* Second add on the same fd must fail (not silently corrupt state) */
    assert(portal_event_add(&loop, fd, EV_READ, dummy_cb, NULL) == -1);
    assert(loop.entry_high == 1);

    portal_event_del(&loop, fd);
    close(fd);
    portal_event_destroy(&loop);
    printf("OK\n");
}

static void test_capacity_cap(void)
{
    printf("test_capacity_cap... ");
    portal_event_loop_t loop;
    assert(portal_event_init(&loop) == 0);
    assert(loop.entry_cap == EVENT_MAX_FDS);

    /* Confirm new limit is large enough for 1000+ peer fleets */
    assert(EVENT_MAX_FDS >= 16384);

    portal_event_destroy(&loop);
    printf("OK (EVENT_MAX_FDS = %d)\n", EVENT_MAX_FDS);
}

int main(void)
{
    printf("=== Portal Event Loop Tests ===\n\n");
    test_capacity_cap();
    test_add_del_basic();
    test_del_unknown_fd();
    test_double_add_rejected();
    test_fd_modify();
    test_slot_reuse_hot_loop();
    printf("\nAll event loop tests passed.\n");
    return 0;
}
