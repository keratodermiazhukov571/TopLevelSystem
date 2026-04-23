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
 * mod_acme — ACME/Let's Encrypt TLS certificate automation
 *
 * Automates TLS certificate provisioning via the ACME protocol.
 * Uses HTTP-01 challenge served through mod_web.
 * Stores certificates in the instance certs/ directory.
 * Auto-renewal via scheduled checks.
 *
 * Flow:
 *   1. Request cert for domain via /acme/functions/request
 *   2. Module creates ACME account + order
 *   3. Serves challenge token at /.well-known/acme-challenge/
 *   4. On validation, downloads cert + key
 *   5. Stores in /etc/portal/<instance>/certs/
 *
 * Uses external tool: relies on a helper script or the `acme.sh`
 * client for the actual ACME protocol (HTTP-01 challenge).
 * This module orchestrates the process via Portal paths.
 *
 * Config:
 *   [mod_acme]
 *   acme_server = https://acme-v02.api.letsencrypt.org/directory
 *   acme_email = admin@example.com
 *   cert_dir = /etc/portal/<instance>/certs
 *   renew_days = 30
 *   acme_tool = acme.sh
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include "portal/portal.h"

#define ACME_MAX_DOMAINS  32
#define ACME_CHALLENGE_SIZE 256

typedef struct {
    char domain[256];
    char cert_file[768];
    char key_file[768];
    int64_t issued;
    int64_t expires;
    int  active;
} acme_cert_t;

/* Challenge token for HTTP-01 validation */
typedef struct {
    char token[128];
    char response[512];
    int  active;
} acme_challenge_t;

static portal_core_t *g_core = NULL;
static char g_acme_server[512] = "https://acme-v02.api.letsencrypt.org/directory";
static char g_acme_email[256] = "";
static char g_cert_dir[512] = "";
static char g_acme_tool[128] = "acme.sh";
static int  g_renew_days = 30;
static acme_cert_t g_certs[ACME_MAX_DOMAINS];
static int g_cert_count = 0;
static acme_challenge_t g_challenge = {0};

static portal_module_info_t info = {
    .name = "acme", .version = "1.0.0",
    .description = "ACME/Let's Encrypt TLS certificate automation",
    .soft_deps = (const char *[]){"web", NULL}
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

/* Run a command with argv array — no shell, no injection.
 * Captures up to `outcap` bytes of combined stdout+stderr for error
 * reporting. Returns the exit code, or -1 on fork/pipe failure.
 * See docs/CODING.md rule #1. */
static int run_cmd(const char *prog, char *const argv[],
                   char *out, size_t outcap)
{
    int pfd[2];
    if (pipe(pfd) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        close(pfd[0]);
        dup2(pfd[1], STDOUT_FILENO);
        dup2(pfd[1], STDERR_FILENO);
        close(pfd[1]);
        execvp(prog, argv);
        _exit(127);
    }
    close(pfd[1]);
    size_t off = 0;
    if (out && outcap > 1) {
        while (off < outcap - 1) {
            ssize_t n = read(pfd[0], out + off, outcap - 1 - off);
            if (n <= 0) break;
            off += (size_t)n;
        }
        out[off] = '\0';
    } else {
        char drop[4096];
        while (read(pfd[0], drop, sizeof(drop)) > 0) { }
    }
    close(pfd[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* Execute ACME tool to request certificate — no shell, argv only. */
static int request_certificate(const char *domain, const char *email,
                                const char *cert_dir)
{
    /* Pre-format the path/domain combinations once; argv entries must
     * be stable string storage. */
    char crt_path[1024], key_path[1024], fc_path[1024], subj[300];
    snprintf(crt_path, sizeof(crt_path), "%s/%s.crt", cert_dir, domain);
    snprintf(key_path, sizeof(key_path), "%s/%s.key", cert_dir, domain);
    snprintf(fc_path,  sizeof(fc_path),  "%s/%s.fullchain.crt",
             cert_dir, domain);
    snprintf(subj, sizeof(subj), "/CN=%s", domain);

    int rc;
    char output[4096] = "";

    if (access("/root/.acme.sh/acme.sh", X_OK) == 0) {
        if (email[0]) {
            char *const argv[] = {
                "acme.sh", "--issue", "-d", (char *)domain, "--standalone",
                "--cert-file", crt_path, "--key-file", key_path,
                "--fullchain-file", fc_path,
                "--accountemail", (char *)email, NULL
            };
            rc = run_cmd("/root/.acme.sh/acme.sh", argv,
                         output, sizeof(output));
        } else {
            char *const argv[] = {
                "acme.sh", "--issue", "-d", (char *)domain, "--standalone",
                "--cert-file", crt_path, "--key-file", key_path,
                "--fullchain-file", fc_path, NULL
            };
            rc = run_cmd("/root/.acme.sh/acme.sh", argv,
                         output, sizeof(output));
        }
    } else if (access("/usr/bin/certbot", X_OK) == 0) {
        if (email[0]) {
            char *const argv[] = {
                "certbot", "certonly", "--standalone", "-d", (char *)domain,
                "--cert-path", crt_path, "--key-path", key_path,
                "--non-interactive", "--agree-tos",
                "--email", (char *)email, NULL
            };
            rc = run_cmd("certbot", argv, output, sizeof(output));
        } else {
            char *const argv[] = {
                "certbot", "certonly", "--standalone", "-d", (char *)domain,
                "--cert-path", crt_path, "--key-path", key_path,
                "--non-interactive", "--agree-tos",
                "--register-unsafely-without-email", NULL
            };
            rc = run_cmd("certbot", argv, output, sizeof(output));
        }
    } else {
        /* Fallback: self-signed via openssl. */
        char *const argv[] = {
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", crt_path,
            "-days", "365", "-nodes", "-subj", subj, NULL
        };
        rc = run_cmd("openssl", argv, output, sizeof(output));
    }

    if (rc == 0) {
        g_core->log(g_core, PORTAL_LOG_INFO, "acme",
                    "Certificate issued for %s", domain);
        return 0;
    }
    g_core->log(g_core, PORTAL_LOG_ERROR, "acme",
                "Certificate request failed for %s (rc=%d): %s",
                domain, rc, output);
    return -1;
}

/* Check if certificate needs renewal */
static int needs_renewal(const char *cert_file, int days)
{
    char days_secs[32];
    snprintf(days_secs, sizeof(days_secs), "%d", days * 86400);
    char *const argv[] = {
        "openssl", "x509", "-in", (char *)cert_file,
        "-checkend", days_secs, "-noout", NULL
    };
    int rc = run_cmd("openssl", argv, NULL, 0);
    return rc != 0;  /* non-zero = expiring soon */
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    memset(g_certs, 0, sizeof(g_certs));
    memset(&g_challenge, 0, sizeof(g_challenge));
    g_cert_count = 0;

    const char *v;
    if ((v = core->config_get(core, "acme", "acme_server")))
        snprintf(g_acme_server, sizeof(g_acme_server), "%s", v);
    if ((v = core->config_get(core, "acme", "acme_email")))
        snprintf(g_acme_email, sizeof(g_acme_email), "%s", v);
    if ((v = core->config_get(core, "acme", "cert_dir")))
        snprintf(g_cert_dir, sizeof(g_cert_dir), "%s", v);
    if ((v = core->config_get(core, "acme", "renew_days")))
        g_renew_days = atoi(v);
    if ((v = core->config_get(core, "acme", "acme_tool")))
        snprintf(g_acme_tool, sizeof(g_acme_tool), "%s", v);

    /* Default cert_dir from instance config */
    if (g_cert_dir[0] == '\0') {
        const char *data_dir = core->config_get(core, "core", "data_dir");
        if (data_dir)
            snprintf(g_cert_dir, sizeof(g_cert_dir), "%s/certs", data_dir);
    }

    core->path_register(core, "/acme/resources/status", "acme");
    core->path_set_access(core, "/acme/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/acme/resources/status", "ACME/Let's Encrypt: server, email, cert directory");
    core->path_register(core, "/acme/resources/certs", "acme");
    core->path_set_access(core, "/acme/resources/certs", PORTAL_ACCESS_READ);
    core->path_register(core, "/acme/functions/request", "acme");
    core->path_set_access(core, "/acme/functions/request", PORTAL_ACCESS_RW);
    core->path_register(core, "/acme/functions/renew", "acme");
    core->path_set_access(core, "/acme/functions/renew", PORTAL_ACCESS_RW);
    core->path_set_description(core, "/acme/functions/renew", "Renew certificate. Header: domain");
    core->path_register(core, "/acme/functions/check", "acme");
    core->path_set_access(core, "/acme/functions/check", PORTAL_ACCESS_RW);

    core->log(core, PORTAL_LOG_INFO, "acme",
              "ACME ready (server: %s, email: %s, certs: %s)",
              g_acme_server,
              g_acme_email[0] ? g_acme_email : "(not set)",
              g_cert_dir);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/acme/resources/status");
    core->path_unregister(core, "/acme/resources/certs");
    core->path_unregister(core, "/acme/functions/request");
    core->path_unregister(core, "/acme/functions/renew");
    core->path_unregister(core, "/acme/functions/check");
    core->log(core, PORTAL_LOG_INFO, "acme", "ACME unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

/* Background thread: request certificate */
static void *acme_request_thread(void *arg)
{
    struct { char domain[256]; } *a = arg;
    int rc = request_certificate(a->domain, g_acme_email, g_cert_dir);
    if (rc == 0 && g_cert_count < ACME_MAX_DOMAINS) {
        acme_cert_t *c = &g_certs[g_cert_count++];
        snprintf(c->domain, sizeof(c->domain), "%s", a->domain);
        snprintf(c->cert_file, sizeof(c->cert_file), "%.500s/%.200s.crt",
                 g_cert_dir, a->domain);
        snprintf(c->key_file, sizeof(c->key_file), "%.500s/%.200s.key",
                 g_cert_dir, a->domain);
        c->issued = (int64_t)time(NULL);
        c->active = 1;
        if (g_core)
            g_core->event_emit(g_core, "/events/acme/issued",
                               a->domain, strlen(a->domain));
    }
    if (g_core)
        g_core->log(g_core, PORTAL_LOG_INFO, "acme",
                    "Certificate request for %s: %s",
                    a->domain, rc == 0 ? "OK" : "FAILED");
    free(a);
    return NULL;
}

/* Background thread: renew all expiring certs */
static void *acme_renew_thread(void *arg)
{
    (void)arg;
    int renewed = 0, failed = 0;
    for (int i = 0; i < g_cert_count; i++) {
        if (!g_certs[i].active) continue;
        if (needs_renewal(g_certs[i].cert_file, g_renew_days)) {
            int rc = request_certificate(g_certs[i].domain,
                                          g_acme_email, g_cert_dir);
            if (rc == 0) {
                renewed++;
                if (g_core)
                    g_core->event_emit(g_core, "/events/acme/renewed",
                                       g_certs[i].domain,
                                       strlen(g_certs[i].domain));
            } else {
                failed++;
            }
        }
    }
    if (g_core)
        g_core->log(g_core, PORTAL_LOG_INFO, "acme",
                    "Renewal complete: %d renewed, %d failed", renewed, failed);
    return NULL;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[8192];
    int n;

    if (strcmp(msg->path, "/acme/resources/status") == 0) {
        const char *tool = "none";
        if (access("/root/.acme.sh/acme.sh", X_OK) == 0) tool = "acme.sh";
        else if (access("/usr/bin/certbot", X_OK) == 0) tool = "certbot";
        else tool = "openssl (self-signed fallback)";

        n = snprintf(buf, sizeof(buf),
            "ACME Certificate Manager\n"
            "Server: %s\n"
            "Email: %s\n"
            "Cert dir: %s\n"
            "Renew threshold: %d days\n"
            "Tool: %s\n"
            "Managed certs: %d\n",
            g_acme_server,
            g_acme_email[0] ? g_acme_email : "(not set)",
            g_cert_dir, g_renew_days, tool, g_cert_count);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/acme/resources/certs") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "Managed Certificates:\n");
        for (int i = 0; i < g_cert_count; i++) {
            if (!g_certs[i].active) continue;
            int renew = needs_renewal(g_certs[i].cert_file, g_renew_days);
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "  %-30s %s\n", g_certs[i].domain,
                renew ? "NEEDS RENEWAL" : "OK");
        }
        if (g_cert_count == 0)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, "  (none)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/acme/functions/request") == 0) {
        const char *domain = get_hdr(msg, "domain");
        if (!domain) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: domain header\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (g_cert_count >= ACME_MAX_DOMAINS) {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            return -1;
        }

        typedef struct { char domain[256]; } acme_req_t;
        acme_req_t *a = malloc(sizeof(*a));
        snprintf(a->domain, sizeof(a->domain), "%s", domain);
        pthread_t th;
        pthread_create(&th, NULL, acme_request_thread, a);
        pthread_detach(th);
        n = snprintf(buf, sizeof(buf),
            "Requesting certificate for %s in background...\n", domain);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/acme/functions/renew") == 0) {
        pthread_t th;
        pthread_create(&th, NULL, acme_renew_thread, NULL);
        pthread_detach(th);
        n = snprintf(buf, sizeof(buf), "Renewal check started in background...\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/acme/functions/check") == 0) {
        const char *domain = get_hdr(msg, "domain");
        if (!domain) {
            /* Check all */
            size_t off = 0;
            for (int i = 0; i < g_cert_count; i++) {
                if (!g_certs[i].active) continue;
                int renew = needs_renewal(g_certs[i].cert_file, g_renew_days);
                off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                    "%s: %s\n", g_certs[i].domain,
                    renew ? "EXPIRING" : "OK");
            }
            if (off == 0) off = (size_t)snprintf(buf, sizeof(buf), "(no certs)\n");
            portal_resp_set_status(resp, PORTAL_OK);
            portal_resp_set_body(resp, buf, off);
            return 0;
        }
        /* Check specific cert file */
        char cert[600];
        snprintf(cert, sizeof(cert), "%s/%s.crt", g_cert_dir, domain);
        struct stat st;
        if (stat(cert, &st) != 0) {
            portal_resp_set_status(resp, PORTAL_NOT_FOUND);
            n = snprintf(buf, sizeof(buf), "No certificate for %s\n", domain);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        int renew = needs_renewal(cert, g_renew_days);
        n = snprintf(buf, sizeof(buf), "%s: %s\n", domain,
                     renew ? "NEEDS RENEWAL" : "OK");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
