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
 * mod_health — Health check system for Portal
 *
 * Standard liveness/readiness probes compatible with
 * Kubernetes, Docker, and load balancers.
 *
 * /health/resources/live    → 200 if core running
 * /health/resources/ready   → 200 if all modules healthy
 * /health/resources/status  → detailed per-module health
 * /health/resources/uptime  → seconds since start
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "portal/portal.h"

static portal_core_t *g_core = NULL;
static time_t g_start_time = 0;

static portal_module_info_t info = {
    .name = "health", .version = "1.0.0",
    .description = "Health check and monitoring",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

/* ── CLI command handlers (registered via portal_cli_register) ── */

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

static int cli_health_status(portal_core_t *core, int fd,
                              const char *line, const char *args)
{
    (void)core; (void)line; (void)args;
    cli_get_path(fd, "/health/resources/status");
    return 0;
}

static int cli_health_live(portal_core_t *core, int fd,
                            const char *line, const char *args)
{
    (void)core; (void)line; (void)args;
    cli_get_path(fd, "/health/resources/live");
    return 0;
}

static int cli_health_ready(portal_core_t *core, int fd,
                             const char *line, const char *args)
{
    (void)core; (void)line; (void)args;
    cli_get_path(fd, "/health/resources/ready");
    return 0;
}

static int cli_uptime(portal_core_t *core, int fd,
                       const char *line, const char *args)
{
    (void)core; (void)line; (void)args;
    cli_get_path(fd, "/health/resources/uptime");
    return 0;
}

static portal_cli_entry_t health_cli_cmds[] = {
    { .words = "health status", .handler = cli_health_status, .summary = "Detailed health status" },
    { .words = "health live",   .handler = cli_health_live,   .summary = "Liveness probe" },
    { .words = "health ready",  .handler = cli_health_ready,  .summary = "Readiness probe" },
    { .words = "health",        .handler = cli_health_status, .summary = "Health status overview" },
    { .words = "uptime",        .handler = cli_uptime,        .summary = "System uptime" },
    { .words = NULL }
};

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    g_start_time = time(NULL);

    core->path_register(core, "/health/resources/live", "health");
    core->path_set_access(core, "/health/resources/live", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/health/resources/live", "Liveness probe: 200 if core running (k8s compatible)");
    core->path_register(core, "/health/resources/ready", "health");
    core->path_set_access(core, "/health/resources/ready", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/health/resources/ready", "Readiness probe: 200 if all modules healthy");
    core->path_register(core, "/health/resources/status", "health");
    core->path_set_access(core, "/health/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/health/resources/status", "Detailed per-module health status");
    core->path_register(core, "/health/resources/uptime", "health");
    core->path_set_access(core, "/health/resources/uptime", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/health/resources/uptime", "Seconds since Portal started");

    /* Register CLI commands */
    for (int i = 0; health_cli_cmds[i].words; i++)
        portal_cli_register(core, &health_cli_cmds[i], "health");

    core->log(core, PORTAL_LOG_INFO, "health", "Health checks ready");
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/health/resources/live");
    core->path_unregister(core, "/health/resources/ready");
    core->path_unregister(core, "/health/resources/status");
    core->path_unregister(core, "/health/resources/uptime");
    portal_cli_unregister_module(core, "health");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[4096];
    int n;

    /* /health/resources/live — always 200 if we can respond */
    if (strcmp(msg->path, "/health/resources/live") == 0) {
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, "ok\n", 3);
        return 0;
    }

    /* /health/resources/uptime */
    if (strcmp(msg->path, "/health/resources/uptime") == 0) {
        time_t uptime = time(NULL) - g_start_time;
        int days = (int)(uptime / 86400);
        int hours = (int)((uptime % 86400) / 3600);
        int mins = (int)((uptime % 3600) / 60);
        int secs = (int)(uptime % 60);
        n = snprintf(buf, sizeof(buf), "%lld seconds (%dd %dh %dm %ds)\n",
                     (long long)uptime, days, hours, mins, secs);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    /* /health/resources/ready — check core status */
    if (strcmp(msg->path, "/health/resources/ready") == 0) {
        portal_msg_t *check = portal_msg_alloc();
        portal_resp_t *check_resp = portal_resp_alloc();
        if (check && check_resp) {
            portal_msg_set_path(check, "/core/status");
            portal_msg_set_method(check, PORTAL_METHOD_GET);
            int rc = core->send(core, check, check_resp);
            if (rc == 0 && check_resp->status == PORTAL_OK) {
                portal_resp_set_status(resp, PORTAL_OK);
                portal_resp_set_body(resp, "ok\n", 3);
            } else {
                portal_resp_set_status(resp, PORTAL_UNAVAILABLE);
                portal_resp_set_body(resp, "not ready\n", 10);
            }
            portal_msg_free(check);
            portal_resp_free(check_resp);
        }
        return 0;
    }

    /* /health/resources/status — detailed */
    if (strcmp(msg->path, "/health/resources/status") == 0) {
        time_t uptime = time(NULL) - g_start_time;
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off,
            "Portal Health Status\n"
            "Uptime: %lld seconds\n"
            "Status: healthy\n\n"
            "Modules:\n", (long long)uptime);

        /* Get module list */
        portal_msg_t *ml = portal_msg_alloc();
        portal_resp_t *mr = portal_resp_alloc();
        if (ml && mr) {
            portal_msg_set_path(ml, "/core/modules");
            portal_msg_set_method(ml, PORTAL_METHOD_GET);
            core->send(core, ml, mr);
            if (mr->body) {
                /* Each module line */
                char *body = mr->body;
                char *line = body;
                while (*line) {
                    char *nl = strchr(line, '\n');
                    if (nl) *nl = '\0';
                    if (strstr(line, "  ") && strlen(line) > 4) {
                        char mname[64];
                        if (sscanf(line, " %63s", mname) == 1 &&
                            strcmp(mname, "Loaded") != 0) {
                            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                                "  %-20s ok\n", mname);
                        }
                    }
                    if (!nl) break;
                    *nl = '\n';
                    line = nl + 1;
                }
            }
            portal_msg_free(ml);
            portal_resp_free(mr);
        }

        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
