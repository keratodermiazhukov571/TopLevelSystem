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
 * mod_cron — Scheduled task executor
 *
 * Runs path calls on configurable intervals.
 * Jobs defined via the path system or config file.
 *
 * Config:
 *   [mod_cron]
 *   max_jobs = 100
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "portal/portal.h"

#define CRON_MAX_JOBS    100
#define CRON_CHECK_SEC   1

typedef struct {
    char    name[64];
    char    path[PORTAL_MAX_PATH_LEN];  /* target path to call */
    int     interval;                    /* seconds between runs */
    int64_t last_run;
    int     enabled;
    int     run_count;
} cron_job_t;

static portal_core_t *g_core = NULL;
static cron_job_t     g_jobs[CRON_MAX_JOBS];
static int            g_job_count = 0;
static int            g_max_jobs = CRON_MAX_JOBS;

static portal_module_info_t info = {
    .name = "cron", .version = "1.0.0",
    .description = "Scheduled task executor",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0)
            return msg->headers[i].value;
    return NULL;
}

/* Timer callback — check and execute due jobs */
static void cron_tick(void *userdata)
{
    (void)userdata;
    int64_t now = (int64_t)time(NULL);

    for (int i = 0; i < g_job_count; i++) {
        if (!g_jobs[i].enabled) continue;
        if (now - g_jobs[i].last_run >= g_jobs[i].interval) {
            g_jobs[i].last_run = now;
            g_jobs[i].run_count++;

            /* Execute: send CALL to the target path */
            portal_msg_t *msg = portal_msg_alloc();
            portal_resp_t *resp = portal_resp_alloc();
            if (msg && resp) {
                portal_msg_set_path(msg, g_jobs[i].path);
                portal_msg_set_method(msg, PORTAL_METHOD_CALL);
                g_core->send(g_core, msg, resp);
                portal_msg_free(msg);
                portal_resp_free(resp);
            }

            g_core->event_emit(g_core, "/events/cron/execute", g_jobs[i].name, strlen(g_jobs[i].name));
            g_core->log(g_core, PORTAL_LOG_DEBUG, "cron",
                        "Executed job '%s' → %s (#%d)",
                        g_jobs[i].name, g_jobs[i].path, g_jobs[i].run_count);
        }
    }
}

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

static int cli_cron_status(portal_core_t *core, int fd,
                            const char *line, const char *args)
{
    (void)core; (void)line; (void)args;
    cli_get_path(fd, "/cron/resources/status");
    return 0;
}

static int cli_cron_jobs(portal_core_t *core, int fd,
                          const char *line, const char *args)
{
    (void)core; (void)line; (void)args;
    cli_get_path(fd, "/cron/resources/jobs");
    return 0;
}

static int cli_cron_add(portal_core_t *core, int fd,
                         const char *line, const char *args)
{
    (void)line;
    char name[64] = {0}, path[PORTAL_MAX_PATH_LEN] = {0};
    int interval = 0;
    if (!args || sscanf(args, "%63s %d %1023s", name, &interval, path) != 3) {
        cli_send(fd, "Usage: cron add <name> <interval_secs> <path>\n");
        return -1;
    }
    portal_msg_t *m = portal_msg_alloc();
    portal_resp_t *r = portal_resp_alloc();
    if (m && r) {
        portal_msg_set_path(m, "/cron/functions/add");
        portal_msg_set_method(m, PORTAL_METHOD_CALL);
        portal_msg_add_header(m, "name", name);
        char is[16]; snprintf(is, sizeof(is), "%d", interval);
        portal_msg_add_header(m, "interval", is);
        portal_msg_add_header(m, "path", path);
        core->send(core, m, r);
        cli_send(fd, r->body ? r->body : "Error\n");
        portal_msg_free(m); portal_resp_free(r);
    }
    return 0;
}

static int cli_cron_remove(portal_core_t *core, int fd,
                            const char *line, const char *args)
{
    (void)line;
    if (!args || !*args) { cli_send(fd, "Usage: cron remove <name>\n"); return -1; }
    portal_msg_t *m = portal_msg_alloc();
    portal_resp_t *r = portal_resp_alloc();
    if (m && r) {
        portal_msg_set_path(m, "/cron/functions/remove");
        portal_msg_set_method(m, PORTAL_METHOD_CALL);
        portal_msg_add_header(m, "name", args);
        core->send(core, m, r);
        cli_send(fd, r->body ? r->body : "Removed\n");
        portal_msg_free(m); portal_resp_free(r);
    }
    return 0;
}

static int cli_cron_trigger(portal_core_t *core, int fd,
                             const char *line, const char *args)
{
    (void)line;
    if (!args || !*args) { cli_send(fd, "Usage: cron trigger <name>\n"); return -1; }
    portal_msg_t *m = portal_msg_alloc();
    portal_resp_t *r = portal_resp_alloc();
    if (m && r) {
        portal_msg_set_path(m, "/cron/functions/trigger");
        portal_msg_set_method(m, PORTAL_METHOD_CALL);
        portal_msg_add_header(m, "name", args);
        core->send(core, m, r);
        cli_send(fd, r->body ? r->body : "Triggered\n");
        portal_msg_free(m); portal_resp_free(r);
    }
    return 0;
}

static portal_cli_entry_t cron_cli_cmds[] = {
    { .words = "cron status",  .handler = cli_cron_status,  .summary = "Cron scheduler status" },
    { .words = "cron jobs",    .handler = cli_cron_jobs,    .summary = "List scheduled cron jobs" },
    { .words = "cron list",    .handler = cli_cron_jobs,    .summary = "List scheduled cron jobs" },
    { .words = "cron add",     .handler = cli_cron_add,     .summary = "Add cron job: <name> <interval> <path>" },
    { .words = "cron remove",  .handler = cli_cron_remove,  .summary = "Remove cron job by name" },
    { .words = "cron trigger", .handler = cli_cron_trigger, .summary = "Force immediate cron job execution" },
    { .words = NULL }
};

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    memset(g_jobs, 0, sizeof(g_jobs));
    g_job_count = 0;

    const char *v;
    if ((v = core->config_get(core, "cron", "max_jobs")))
        g_max_jobs = atoi(v);

    core->path_register(core, "/cron/resources/status", "cron");
    core->path_set_access(core, "/cron/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/cron/resources/status", "Scheduler status: active job count");
    core->path_register(core, "/cron/resources/jobs", "cron");
    core->path_set_access(core, "/cron/resources/jobs", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/cron/resources/jobs", "List jobs: name, interval, path, run count, next run");
    core->path_register(core, "/cron/functions/add", "cron");
    core->path_set_access(core, "/cron/functions/add", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/cron/functions/add", "Add periodic job. Headers: name, path, interval (seconds)");
    core->path_register(core, "/cron/functions/remove", "cron");
    core->path_set_access(core, "/cron/functions/remove", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/cron/functions/remove", "Remove job. Header: name");
    core->path_register(core, "/cron/functions/trigger", "cron");
    core->path_set_access(core, "/cron/functions/trigger", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/cron/functions/trigger", "Force immediate run. Header: name");

    /* Autonomous 1 Hz tick.
     *
     * Previously this module relied on external traffic to /cron/...
     * hitting portal_module_handle() to drive cron_tick(). On a host
     * that doesn't get any HTTP/CLI probes to /cron/... scheduled jobs
     * never fired, regardless of their interval. That broke every
     * module that depends on mod_cron for periodic work — for example,
     * a health-probe job scheduled every 60s could not detect service
     * failure without something externally polling /cron/resources/jobs
     * in a loop.
     *
     * Registering a 1 Hz timer on the core event loop makes cron_tick()
     * run once per second regardless of external traffic. The tick
     * body is cheap: iterate g_jobs[], check (now - last_run) against
     * each interval, dispatch any that are due via core->send(). For
     * g_job_count < 100 it's a few hundred ns per tick with no I/O
     * on the common path. No new allocation, no blocking syscall. */
    core->timer_add(core, 1.0, cron_tick, NULL);

    /* Register CLI commands */
    for (int i = 0; cron_cli_cmds[i].words; i++)
        portal_cli_register(core, &cron_cli_cmds[i], "cron");

    core->log(core, PORTAL_LOG_INFO, "cron",
              "Cron scheduler ready (max: %d jobs, autonomous 1 Hz tick)", g_max_jobs);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/cron/resources/status");
    core->path_unregister(core, "/cron/resources/jobs");
    core->path_unregister(core, "/cron/functions/add");
    core->path_unregister(core, "/cron/functions/remove");
    core->path_unregister(core, "/cron/functions/trigger");
    portal_cli_unregister_module(core, "cron");
    core->log(core, PORTAL_LOG_INFO, "cron", "Cron unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[8192];
    int n;

    /* Check due jobs on every request */
    cron_tick(NULL);

    if (strcmp(msg->path, "/cron/resources/status") == 0) {
        int active = 0;
        for (int i = 0; i < g_job_count; i++)
            if (g_jobs[i].enabled) active++;
        n = snprintf(buf, sizeof(buf),
            "Cron Scheduler\n"
            "Jobs: %d active / %d total (max %d)\n",
            active, g_job_count, g_max_jobs);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/cron/resources/jobs") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "Scheduled Jobs:\n");
        for (int i = 0; i < g_job_count; i++) {
            if (g_jobs[i].enabled) {
                int64_t next = g_jobs[i].last_run + g_jobs[i].interval - (int64_t)time(NULL);
                if (next < 0) next = 0;
                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "  %-20s every %ds → %s (runs: %d, next: %llds)\n",
                    g_jobs[i].name, g_jobs[i].interval, g_jobs[i].path,
                    g_jobs[i].run_count, (long long)next);
            }
        }
        if (g_job_count == 0)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, "  (none)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/cron/functions/add") == 0) {
        const char *name = get_hdr(msg, "name");
        const char *path = get_hdr(msg, "path");
        const char *int_s = get_hdr(msg, "interval");
        if (!name || !path || !int_s) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: name, path, interval headers\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (g_job_count >= g_max_jobs) {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            n = snprintf(buf, sizeof(buf), "Max jobs reached\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        cron_job_t *job = &g_jobs[g_job_count++];
        snprintf(job->name, sizeof(job->name), "%s", name);
        snprintf(job->path, sizeof(job->path), "%s", path);
        job->interval = atoi(int_s);
        job->last_run = (int64_t)time(NULL);
        job->enabled = 1;
        job->run_count = 0;

        core->event_emit(core, "/events/cron/add", name, strlen(name));
        portal_resp_set_status(resp, PORTAL_CREATED);
        n = snprintf(buf, sizeof(buf), "Job '%s' added: every %ds → %s\n",
                     name, job->interval, path);
        portal_resp_set_body(resp, buf, (size_t)n);
        core->log(core, PORTAL_LOG_INFO, "cron", "Added job '%s' every %ds → %s",
                  name, job->interval, path);
        return 0;
    }

    if (strcmp(msg->path, "/cron/functions/remove") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        for (int i = 0; i < g_job_count; i++) {
            if (g_jobs[i].enabled && strcmp(g_jobs[i].name, name) == 0) {
                g_jobs[i].enabled = 0;
                core->event_emit(core, "/events/cron/remove", name, strlen(name));
                portal_resp_set_status(resp, PORTAL_OK);
                n = snprintf(buf, sizeof(buf), "Job '%s' removed\n", name);
                portal_resp_set_body(resp, buf, (size_t)n);
                return 0;
            }
        }
        portal_resp_set_status(resp, PORTAL_NOT_FOUND);
        return -1;
    }

    if (strcmp(msg->path, "/cron/functions/trigger") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        for (int i = 0; i < g_job_count; i++) {
            if (g_jobs[i].enabled && strcmp(g_jobs[i].name, name) == 0) {
                g_jobs[i].last_run = 0;  /* force next tick */
                cron_tick(NULL);
                portal_resp_set_status(resp, PORTAL_OK);
                n = snprintf(buf, sizeof(buf), "Triggered '%s'\n", name);
                portal_resp_set_body(resp, buf, (size_t)n);
                return 0;
            }
        }
        portal_resp_set_status(resp, PORTAL_NOT_FOUND);
        return -1;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
