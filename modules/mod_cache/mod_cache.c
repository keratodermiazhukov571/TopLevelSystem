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
 * mod_cache — In-memory key-value store with TTL
 *
 * Ultra-fast hash table cache accessible via paths.
 * Supports TTL expiry, stats, and key listing.
 * Thread-safe for use from module thread pools.
 *
 * Config:
 *   [mod_cache]
 *   max_entries = 10000
 *   cleanup_interval = 30
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include "portal/portal.h"

#define CACHE_DEFAULT_MAX    10000
#define CACHE_DEFAULT_TTL    0       /* 0 = no expiry */
#define CACHE_CLEANUP_SEC    30

typedef struct {
    char    *key;
    char    *value;
    int64_t  expires;   /* 0 = never */
    int      active;
} cache_entry_t;

static portal_core_t *g_core = NULL;
static cache_entry_t *g_entries = NULL;
static int             g_max = CACHE_DEFAULT_MAX;
static int             g_count = 0;
static int64_t         g_hits = 0;
static int64_t         g_misses = 0;
static int64_t         g_sets = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static portal_module_info_t info = {
    .name = "cache", .version = "1.0.0",
    .description = "In-memory key-value cache with TTL",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

/* --- Internal ops --- */

static cache_entry_t *cache_find(const char *key)
{
    for (int i = 0; i < g_max; i++) {
        if (g_entries[i].active && g_entries[i].key &&
            strcmp(g_entries[i].key, key) == 0) {
            /* Check expiry */
            if (g_entries[i].expires > 0 &&
                (int64_t)time(NULL) > g_entries[i].expires) {
                free(g_entries[i].key); free(g_entries[i].value);
                g_entries[i].active = 0;
                g_count--;
                return NULL;
            }
            return &g_entries[i];
        }
    }
    return NULL;
}

static int cache_set(const char *key, const char *value, int ttl)
{
    pthread_mutex_lock(&g_lock);

    /* Update existing */
    cache_entry_t *e = cache_find(key);
    if (e) {
        free(e->value);
        e->value = strdup(value);
        e->expires = ttl > 0 ? (int64_t)time(NULL) + ttl : 0;
        g_sets++;
        pthread_mutex_unlock(&g_lock);
        return 0;
    }

    /* Find free slot */
    if (g_count >= g_max) {
        pthread_mutex_unlock(&g_lock);
        return -1;
    }
    for (int i = 0; i < g_max; i++) {
        if (!g_entries[i].active) {
            g_entries[i].key = strdup(key);
            g_entries[i].value = strdup(value);
            g_entries[i].expires = ttl > 0 ? (int64_t)time(NULL) + ttl : 0;
            g_entries[i].active = 1;
            g_count++;
            g_sets++;
            pthread_mutex_unlock(&g_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_lock);
    return -1;
}

static const char *cache_get(const char *key)
{
    pthread_mutex_lock(&g_lock);
    cache_entry_t *e = cache_find(key);
    if (e) { g_hits++; pthread_mutex_unlock(&g_lock); return e->value; }
    g_misses++;
    pthread_mutex_unlock(&g_lock);
    return NULL;
}

static int cache_del(const char *key)
{
    pthread_mutex_lock(&g_lock);
    cache_entry_t *e = cache_find(key);
    if (e) {
        free(e->key); free(e->value);
        e->key = NULL; e->value = NULL;
        e->active = 0;
        g_count--;
        pthread_mutex_unlock(&g_lock);
        return 0;
    }
    pthread_mutex_unlock(&g_lock);
    return -1;
}

static void cache_flush(void)
{
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_max; i++) {
        if (g_entries[i].active) {
            free(g_entries[i].key); free(g_entries[i].value);
            g_entries[i].active = 0;
        }
    }
    g_count = 0;
    pthread_mutex_unlock(&g_lock);
}

static int cache_cleanup(void)
{
    int cleaned = 0;
    int64_t now = (int64_t)time(NULL);
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_max; i++) {
        if (g_entries[i].active && g_entries[i].expires > 0 &&
            now > g_entries[i].expires) {
            free(g_entries[i].key); free(g_entries[i].value);
            g_entries[i].active = 0;
            g_count--;
            cleaned++;
        }
    }
    pthread_mutex_unlock(&g_lock);
    return cleaned;
}

/* --- Helper --- */

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0)
            return msg->headers[i].value;
    return NULL;
}

/* --- Module lifecycle --- */

/* ── CLI command handlers (registered via portal_cli_register) ── */

static void cli_send(int fd, const char *s)
{
    if (s) write(fd, s, strlen(s));
}

static void cli_get_path(int fd, const char *path)
{
    portal_msg_t *m = portal_msg_alloc();
    portal_resp_t *r = portal_resp_alloc();
    if (!m || !r) return;
    portal_msg_set_path(m, path);
    portal_msg_set_method(m, PORTAL_METHOD_GET);
    g_core->send(g_core, m, r);
    if (r->body) write(fd, r->body, r->body_len);
    portal_msg_free(m); portal_resp_free(r);
}

static int cli_cache_get(portal_core_t *core, int fd,
                          const char *line, const char *args)
{
    (void)core; (void)line;
    if (!args || !*args) { cli_send(fd, "Usage: cache get <key>\n"); return -1; }
    portal_msg_t *m = portal_msg_alloc();
    portal_resp_t *r = portal_resp_alloc();
    if (m && r) {
        portal_msg_set_path(m, "/cache/functions/get");
        portal_msg_set_method(m, PORTAL_METHOD_CALL);
        portal_msg_add_header(m, "key", args);
        core->send(core, m, r);
        if (r->status == PORTAL_OK && r->body) {
            write(fd, r->body, r->body_len);
            write(fd, "\n", 1);
        } else {
            cli_send(fd, "(not found)\n");
        }
        portal_msg_free(m); portal_resp_free(r);
    }
    return 0;
}

static int cli_cache_set(portal_core_t *core, int fd,
                          const char *line, const char *args)
{
    (void)line;
    char k[128] = {0}, v[1024] = {0};
    if (!args || sscanf(args, "%127s %1023[^\n]", k, v) < 2) {
        cli_send(fd, "Usage: cache set <key> <value> [ttl]\n");
        return -1;
    }
    int ttl = 0;
    char *last_space = strrchr(v, ' ');
    if (last_space && atoi(last_space + 1) > 0) {
        ttl = atoi(last_space + 1);
        *last_space = '\0';
    }
    portal_msg_t *m = portal_msg_alloc();
    portal_resp_t *r = portal_resp_alloc();
    if (m && r) {
        portal_msg_set_path(m, "/cache/functions/set");
        portal_msg_set_method(m, PORTAL_METHOD_CALL);
        portal_msg_add_header(m, "key", k);
        portal_msg_add_header(m, "value", v);
        if (ttl > 0) {
            char ts[16]; snprintf(ts, sizeof(ts), "%d", ttl);
            portal_msg_add_header(m, "ttl", ts);
        }
        core->send(core, m, r);
        cli_send(fd, r->body ? r->body : "Error\n");
        portal_msg_free(m); portal_resp_free(r);
    }
    return 0;
}

static int cli_cache_del(portal_core_t *core, int fd,
                          const char *line, const char *args)
{
    (void)line;
    if (!args || !*args) { cli_send(fd, "Usage: cache del <key>\n"); return -1; }
    portal_msg_t *m = portal_msg_alloc();
    portal_resp_t *r = portal_resp_alloc();
    if (m && r) {
        portal_msg_set_path(m, "/cache/functions/del");
        portal_msg_set_method(m, PORTAL_METHOD_CALL);
        portal_msg_add_header(m, "key", args);
        core->send(core, m, r);
        cli_send(fd, r->body ? r->body : "Deleted\n");
        portal_msg_free(m); portal_resp_free(r);
    }
    return 0;
}

static int cli_cache_keys(portal_core_t *core, int fd,
                           const char *line, const char *args)
{
    (void)core; (void)line; (void)args;
    cli_get_path(fd, "/cache/resources/keys");
    return 0;
}

static int cli_cache_status(portal_core_t *core, int fd,
                             const char *line, const char *args)
{
    (void)core; (void)line; (void)args;
    cli_get_path(fd, "/cache/resources/status");
    return 0;
}

static int cli_cache_flush(portal_core_t *core, int fd,
                            const char *line, const char *args)
{
    (void)line; (void)args;
    portal_msg_t *m = portal_msg_alloc();
    portal_resp_t *r = portal_resp_alloc();
    if (m && r) {
        portal_msg_set_path(m, "/cache/functions/flush");
        portal_msg_set_method(m, PORTAL_METHOD_CALL);
        core->send(core, m, r);
        cli_send(fd, r->body ? r->body : "Flushed\n");
        portal_msg_free(m); portal_resp_free(r);
    }
    return 0;
}

static portal_cli_entry_t cache_cli_cmds[] = {
    { .words = "cache get",     .handler = cli_cache_get,    .summary = "Get cache value by key" },
    { .words = "cache set",     .handler = cli_cache_set,    .summary = "Set cache key value [ttl]" },
    { .words = "cache del",     .handler = cli_cache_del,    .summary = "Delete cache key" },
    { .words = "cache keys",    .handler = cli_cache_keys,   .summary = "List all cache keys" },
    { .words = "cache status",  .handler = cli_cache_status, .summary = "Cache statistics" },
    { .words = "cache flush",   .handler = cli_cache_flush,  .summary = "Clear all cache entries" },
    { .words = NULL }
};

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    const char *v;
    if ((v = core->config_get(core, "cache", "max_entries")))
        g_max = atoi(v);
    if (g_max < 1) g_max = CACHE_DEFAULT_MAX;

    g_entries = calloc((size_t)g_max, sizeof(cache_entry_t));
    g_count = 0; g_hits = 0; g_misses = 0; g_sets = 0;

    core->path_register(core, "/cache/resources/status", "cache");
    core->path_set_access(core, "/cache/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/cache/resources/status", "Cache stats: entries, hits, misses, memory");
    core->path_register(core, "/cache/resources/keys", "cache");
    core->path_set_access(core, "/cache/resources/keys", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/cache/resources/keys", "List all cache keys with TTL");
    core->path_register(core, "/cache/functions/get", "cache");
    core->path_set_access(core, "/cache/functions/get", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/cache/functions/get", "Get cache value. Header: key");
    core->path_register(core, "/cache/functions/set", "cache");
    core->path_set_access(core, "/cache/functions/set", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/cache/functions/set", "Set cache key. Headers: key, value, optional: ttl (seconds)");
    core->path_register(core, "/cache/functions/del", "cache");
    core->path_set_access(core, "/cache/functions/del", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/cache/functions/del", "Delete cache key. Header: key");
    core->path_register(core, "/cache/functions/flush", "cache");
    core->path_set_access(core, "/cache/functions/flush", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/cache/functions/flush", "Clear all cache entries");

    /* Register CLI commands */
    for (int i = 0; cache_cli_cmds[i].words; i++)
        portal_cli_register(core, &cache_cli_cmds[i], "cache");

    core->log(core, PORTAL_LOG_INFO, "cache",
              "Cache ready (max: %d entries)", g_max);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    cache_flush();
    free(g_entries); g_entries = NULL;
    core->path_unregister(core, "/cache/resources/status");
    core->path_unregister(core, "/cache/resources/keys");
    core->path_unregister(core, "/cache/functions/get");
    core->path_unregister(core, "/cache/functions/set");
    core->path_unregister(core, "/cache/functions/del");
    core->path_unregister(core, "/cache/functions/flush");
    portal_cli_unregister_module(core, "cache");
    core->log(core, PORTAL_LOG_INFO, "cache", "Cache unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    (void)core;
    char buf[8192];
    int n;

    if (strcmp(msg->path, "/cache/resources/status") == 0) {
        cache_cleanup();  /* clean expired entries on status check */
        double hit_rate = (g_hits + g_misses) > 0
            ? (double)g_hits / (double)(g_hits + g_misses) * 100.0 : 0.0;
        n = snprintf(buf, sizeof(buf),
            "Cache Status\n"
            "Entries: %d / %d\n"
            "Hits: %lld\n"
            "Misses: %lld\n"
            "Sets: %lld\n"
            "Hit rate: %.1f%%\n",
            g_count, g_max,
            (long long)g_hits, (long long)g_misses,
            (long long)g_sets, hit_rate);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/cache/resources/keys") == 0) {
        size_t off = 0;
        pthread_mutex_lock(&g_lock);
        for (int i = 0; i < g_max && off < sizeof(buf) - 128; i++) {
            if (g_entries[i].active)
                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "%s\n", g_entries[i].key);
        }
        pthread_mutex_unlock(&g_lock);
        if (off == 0) off = (size_t)snprintf(buf, sizeof(buf), "(empty)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/cache/functions/get") == 0) {
        const char *key = get_hdr(msg, "key");
        if (!key) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        const char *val = cache_get(key);
        if (val) {
            portal_resp_set_status(resp, PORTAL_OK);
            portal_resp_set_body(resp, val, strlen(val));
        } else {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            n = snprintf(buf, sizeof(buf), "Key not found: %s\n", key);
            portal_resp_set_body(resp, buf, (size_t)n);
        }
        return 0;
    }

    if (strcmp(msg->path, "/cache/functions/set") == 0) {
        const char *key = get_hdr(msg, "key");
        const char *val = get_hdr(msg, "value");
        const char *ttl_s = get_hdr(msg, "ttl");
        if (!key || !val) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        int ttl = ttl_s ? atoi(ttl_s) : CACHE_DEFAULT_TTL;
        if (cache_set(key, val, ttl) == 0) {
            core->event_emit(core, "/events/cache/set", key, strlen(key));
            portal_resp_set_status(resp, PORTAL_OK);
            n = snprintf(buf, sizeof(buf), "OK\n");
            portal_resp_set_body(resp, buf, (size_t)n);
        } else {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            n = snprintf(buf, sizeof(buf), "Cache full\n");
            portal_resp_set_body(resp, buf, (size_t)n);
        }
        return 0;
    }

    if (strcmp(msg->path, "/cache/functions/del") == 0) {
        const char *key = get_hdr(msg, "key");
        if (!key) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        cache_del(key);
        core->event_emit(core, "/events/cache/del", key, strlen(key));
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "Deleted\n");
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/cache/functions/flush") == 0) {
        cache_flush();
        core->event_emit(core, "/events/cache/flush", "all", 3);
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "Flushed\n");
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
