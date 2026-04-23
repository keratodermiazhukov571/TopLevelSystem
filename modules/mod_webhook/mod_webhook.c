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
 * mod_webhook — Webhook dispatcher
 *
 * Register webhook URLs, dispatch HTTP POST notifications
 * on events or manual triggers. Supports retry on failure.
 *
 * Config:
 *   [mod_webhook]
 *   max_hooks = 64
 *   timeout = 5
 *   retry = 3
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include "portal/portal.h"

#ifdef HAS_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#define WH_MAX_HOOKS   64
#define WH_TIMEOUT     5
#define WH_RETRY       3
#define WH_BUF_SIZE    8192

typedef struct {
    char    name[64];
    char    url[512];
    char    host[256];
    int     port;
    int     tls;        /* 1 = https://, 0 = http:// */
    char    path[256];
    char    event[PORTAL_MAX_PATH_LEN];  /* subscribe to this event */
    int     active;
    int64_t sent;
    int64_t failed;
} webhook_t;

static portal_core_t *g_core = NULL;
static webhook_t      g_hooks[WH_MAX_HOOKS];
static int            g_count = 0;
static int            g_max = WH_MAX_HOOKS;
static int            g_timeout = WH_TIMEOUT;
static int            g_retry = WH_RETRY;

#ifdef HAS_SSL
static SSL_CTX       *g_ssl_ctx = NULL;
static int            g_tls_verify = 1;   /* set to 0 to allow self-signed */
#endif

static portal_module_info_t info = {
    .name = "webhook", .version = "1.0.0",
    .description = "Webhook dispatcher (HTTP/HTTPS POST)",
    .soft_deps = NULL
};
portal_module_info_t *portal_module_info(void) { return &info; }

static const char *get_hdr(const portal_msg_t *msg, const char *key)
{
    for (uint16_t i = 0; i < msg->header_count; i++)
        if (strcmp(msg->headers[i].key, key) == 0) return msg->headers[i].value;
    return NULL;
}

static webhook_t *find_hook(const char *name)
{
    for (int i = 0; i < g_count; i++)
        if (g_hooks[i].active && strcmp(g_hooks[i].name, name) == 0)
            return &g_hooks[i];
    return NULL;
}

static int parse_url(const char *url, char *host, size_t hlen,
                     int *port, char *path, size_t plen, int *tls)
{
    const char *p = url;
    int default_port = 80;
    if (tls) *tls = 0;
    if (strncmp(p, "http://", 7) == 0) {
        p += 7;
        default_port = 80;
        if (tls) *tls = 0;
    } else if (strncmp(p, "https://", 8) == 0) {
        p += 8;
        default_port = 443;
        if (tls) *tls = 1;
    }

    const char *colon = strchr(p, ':');
    const char *slash = strchr(p, '/');

    if (colon && (!slash || colon < slash)) {
        size_t hl = (size_t)(colon - p);
        if (hl >= hlen) hl = hlen - 1;
        memcpy(host, p, hl); host[hl] = '\0';
        *port = atoi(colon + 1);
    } else if (slash) {
        size_t hl = (size_t)(slash - p);
        if (hl >= hlen) hl = hlen - 1;
        memcpy(host, p, hl); host[hl] = '\0';
        *port = default_port;
    } else {
        snprintf(host, hlen, "%s", p);
        *port = default_port;
    }
    if (slash) snprintf(path, plen, "%s", slash);
    else snprintf(path, plen, "/");
    return 0;
}

/* Send HTTP[S] POST to webhook URL.
 *
 * For HTTPS, wraps the connected socket in OpenSSL using the shared
 * g_ssl_ctx (created at module load when HAS_SSL is built in).
 * Cert verification is gated by g_tls_verify (default on); operators
 * with self-signed receivers can flip tls_verify=false in
 * mod_webhook.conf. SNI is set so make.com/Cloudflare-style
 * multi-tenant endpoints route correctly. */
static int webhook_post(webhook_t *hook, const char *body, size_t body_len)
{
    struct hostent *he = gethostbyname(hook->host);
    if (!he) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = {g_timeout, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)hook->port);
    memcpy(&addr.sin_addr, he->h_addr, (size_t)he->h_length);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

#ifdef HAS_SSL
    SSL *ssl = NULL;
    if (hook->tls) {
        if (!g_ssl_ctx) {
            close(fd);
            return -1;
        }
        ssl = SSL_new(g_ssl_ctx);
        if (!ssl) { close(fd); return -1; }
        SSL_set_fd(ssl, fd);
        /* SNI — required by virtually every TLS terminator on the public
         * web (Cloudflare, AWS ALB, make.com hooks, etc.). */
        SSL_set_tlsext_host_name(ssl, hook->host);
        if (g_tls_verify) {
            /* Set the expected server name for hostname verification. */
            X509_VERIFY_PARAM *vp = SSL_get0_param(ssl);
            X509_VERIFY_PARAM_set_hostflags(vp, 0);
            X509_VERIFY_PARAM_set1_host(vp, hook->host, 0);
            SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
        } else {
            SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
        }
        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl);
            close(fd);
            return -1;
        }
    }
#else
    if (hook->tls) {
        /* TLS requested but compiled without OpenSSL. */
        close(fd);
        return -1;
    }
#endif

    char req[WH_BUF_SIZE];
    int rlen = snprintf(req, sizeof(req),
        "POST %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "User-Agent: Portal-Webhook/1.0\r\n"
        "Connection: close\r\n"
        "\r\n",
        hook->path, hook->host, body_len);

    int wrc = -1;
    char resp[512];
    ssize_t rd = -1;

#ifdef HAS_SSL
    if (ssl) {
        if (SSL_write(ssl, req, rlen) <= 0) goto bail_ssl;
        if (body_len > 0 && SSL_write(ssl, body, (int)body_len) <= 0) goto bail_ssl;
        rd = SSL_read(ssl, resp, sizeof(resp) - 1);
        wrc = 0;
    bail_ssl:
        SSL_shutdown(ssl);
        SSL_free(ssl);
    } else
#endif
    {
        if (write(fd, req, (size_t)rlen) < 0) { close(fd); return -1; }
        if (body_len > 0 && write(fd, body, body_len) < 0) { close(fd); return -1; }
        rd = read(fd, resp, sizeof(resp) - 1);
        wrc = 0;
    }

    close(fd);
    if (wrc != 0) return -1;

    if (rd > 0) {
        resp[rd] = '\0';
        /* Check HTTP status: 2xx = success */
        int status = 0;
        if (sscanf(resp, "HTTP/%*s %d", &status) == 1 && status >= 200 && status < 300)
            return 0;
    }
    return -1;
}

static int send_webhook(webhook_t *hook, const char *body, size_t body_len)
{
    for (int attempt = 0; attempt < g_retry; attempt++) {
        if (webhook_post(hook, body, body_len) == 0) {
            hook->sent++;
            return 0;
        }
    }
    hook->failed++;
    return -1;
}

/* Background webhook send */
typedef struct {
    webhook_t *hook;
    char       payload[4096];
    size_t     plen;
} webhook_job_t;

static void *webhook_send_thread(void *arg)
{
    webhook_job_t *job = arg;
    send_webhook(job->hook, job->payload, job->plen);
    free(job);
    return NULL;
}

/* Event handler: dispatch to matching webhooks (non-blocking) */
static void webhook_event_handler(const portal_msg_t *msg, void *userdata)
{
    (void)userdata;
    for (int i = 0; i < g_count; i++) {
        if (!g_hooks[i].active) continue;
        if (g_hooks[i].event[0] == '\0') continue;
        if (strcmp(g_hooks[i].event, msg->path) == 0 ||
            (g_hooks[i].event[strlen(g_hooks[i].event) - 1] == '*' &&
             strncmp(g_hooks[i].event, msg->path, strlen(g_hooks[i].event) - 1) == 0)) {
            webhook_job_t *job = malloc(sizeof(*job));
            if (!job) continue;
            job->hook = &g_hooks[i];
            job->plen = (size_t)snprintf(job->payload, sizeof(job->payload),
                "{\"event\":\"%s\",\"hook\":\"%s\",\"data\":\"%.*s\"}",
                msg->path, g_hooks[i].name,
                msg->body_len > 512 ? 512 : (int)msg->body_len,
                msg->body ? (const char *)msg->body : "");
            pthread_t th;
            pthread_create(&th, NULL, webhook_send_thread, job);
            pthread_detach(th);
        }
    }
}

int portal_module_load(portal_core_t *core)
{
    g_core = core;
    memset(g_hooks, 0, sizeof(g_hooks));
    g_count = 0;

    const char *v;
    if ((v = core->config_get(core, "webhook", "max_hooks")))
        g_max = atoi(v);
    if ((v = core->config_get(core, "webhook", "timeout")))
        g_timeout = atoi(v);
    if ((v = core->config_get(core, "webhook", "retry")))
        g_retry = atoi(v);

#ifdef HAS_SSL
    /* tls_verify defaults to true; flip to false in mod_webhook.conf for
     * receivers behind self-signed certs. Never flip it for make.com /
     * Slack / public webhook receivers — those must be verified. */
    if ((v = core->config_get(core, "webhook", "tls_verify"))) {
        g_tls_verify = (atoi(v) != 0 ||
                        strcasecmp(v, "true") == 0 ||
                        strcasecmp(v, "yes") == 0) ? 1 : 0;
    }
    SSL_library_init();
    SSL_load_error_strings();
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (g_ssl_ctx) {
        /* Use system trust store; on AlmaLinux/RHEL/Debian this loads
         * /etc/pki or /etc/ssl/certs automatically. */
        SSL_CTX_set_default_verify_paths(g_ssl_ctx);
        SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);
        core->log(core, PORTAL_LOG_INFO, "webhook",
                  "TLS client ctx ready (verify: %s)",
                  g_tls_verify ? "on" : "off");
    } else {
        core->log(core, PORTAL_LOG_WARN, "webhook",
                  "Failed to initialize TLS client ctx — https:// hooks will be rejected");
    }
#endif

    core->path_register(core, "/webhook/resources/status", "webhook");
    core->path_set_access(core, "/webhook/resources/status", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/webhook/resources/status", "Webhook dispatcher: hook count, timeout, retries");
    core->path_register(core, "/webhook/resources/hooks", "webhook");
    core->path_set_access(core, "/webhook/resources/hooks", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/webhook/resources/hooks", "List registered webhooks");
    core->path_register(core, "/webhook/functions/register", "webhook");
    core->path_set_access(core, "/webhook/functions/register", PORTAL_ACCESS_RW);
    core->path_add_label(core, "/webhook/functions/register", "hub-admin");
    core->path_register(core, "/webhook/functions/unregister", "webhook");
    core->path_set_access(core, "/webhook/functions/unregister", PORTAL_ACCESS_RW);
    core->path_add_label(core, "/webhook/functions/unregister", "hub-admin");
    core->path_register(core, "/webhook/functions/send", "webhook");
    core->path_set_access(core, "/webhook/functions/send", PORTAL_ACCESS_RW);
    core->path_add_label(core, "/webhook/functions/send", "hub-admin");
    core->path_register(core, "/webhook/functions/test", "webhook");
    core->path_set_access(core, "/webhook/functions/test", PORTAL_ACCESS_RW);
    core->path_add_label(core, "/webhook/functions/test", "hub-admin");

    /* Subscribe to all events */
    core->subscribe(core, "/events/*", webhook_event_handler, NULL);

    core->log(core, PORTAL_LOG_INFO, "webhook",
              "Webhook dispatcher ready (max: %d, timeout: %ds, retry: %d)",
              g_max, g_timeout, g_retry);
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->unsubscribe(core, "/events/*", webhook_event_handler);

    core->path_unregister(core, "/webhook/resources/status");
    core->path_unregister(core, "/webhook/resources/hooks");
    core->path_unregister(core, "/webhook/functions/register");
    core->path_unregister(core, "/webhook/functions/unregister");
    core->path_unregister(core, "/webhook/functions/send");
    core->path_unregister(core, "/webhook/functions/test");
#ifdef HAS_SSL
    if (g_ssl_ctx) { SSL_CTX_free(g_ssl_ctx); g_ssl_ctx = NULL; }
#endif
    core->log(core, PORTAL_LOG_INFO, "webhook", "Webhook dispatcher unloaded");
    g_core = NULL;
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    char buf[8192];
    int n;

    if (strcmp(msg->path, "/webhook/resources/status") == 0) {
        int active = 0;
        int64_t ts = 0, tf = 0;
        for (int i = 0; i < g_count; i++) {
            if (!g_hooks[i].active) continue;
            active++;
            ts += g_hooks[i].sent;
            tf += g_hooks[i].failed;
        }
        n = snprintf(buf, sizeof(buf),
            "Webhook Dispatcher\n"
            "Hooks: %d (max %d)\n"
            "Timeout: %ds, Retry: %d\n"
            "Total sent: %lld\n"
            "Total failed: %lld\n",
            active, g_max, g_timeout, g_retry,
            (long long)ts, (long long)tf);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/webhook/resources/hooks") == 0) {
        size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "Webhooks:\n");
        for (int i = 0; i < g_count; i++) {
            if (!g_hooks[i].active) continue;
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "  %-16s → %s:%d%s  event: %s  sent: %lld  failed: %lld\n",
                g_hooks[i].name, g_hooks[i].host, g_hooks[i].port,
                g_hooks[i].path,
                g_hooks[i].event[0] ? g_hooks[i].event : "(manual)",
                (long long)g_hooks[i].sent, (long long)g_hooks[i].failed);
        }
        if (g_count == 0)
            off += (size_t)snprintf(buf + off, sizeof(buf) - off, "  (none)\n");
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, off);
        return 0;
    }

    if (strcmp(msg->path, "/webhook/functions/register") == 0) {
        const char *name = get_hdr(msg, "name");
        const char *url = get_hdr(msg, "url");
        const char *event = get_hdr(msg, "event");
        if (!name || !url) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf),
                "Need: name, url headers (optional: event)\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (find_hook(name)) {
            portal_resp_set_status(resp, PORTAL_CONFLICT);
            n = snprintf(buf, sizeof(buf), "Hook '%s' already exists\n", name);
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        if (g_count >= g_max) {
            portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
            return -1;
        }

        webhook_t *h = &g_hooks[g_count++];
        snprintf(h->name, sizeof(h->name), "%s", name);
        snprintf(h->url, sizeof(h->url), "%s", url);
        parse_url(url, h->host, sizeof(h->host),
                  &h->port, h->path, sizeof(h->path), &h->tls);
#ifndef HAS_SSL
        if (h->tls) {
            g_count--;   /* roll back the slot reservation */
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf),
                "https:// URLs require Portal built with HAS_SSL=yes\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
#endif
        if (event) snprintf(h->event, sizeof(h->event), "%s", event);
        else h->event[0] = '\0';
        h->active = 1;
        h->sent = h->failed = 0;

        core->event_emit(core, "/events/webhook/register", name, strlen(name));
        portal_resp_set_status(resp, PORTAL_CREATED);
        n = snprintf(buf, sizeof(buf), "Hook '%s' registered → %s://%s:%d%s%s%s",
                     name, h->tls ? "https" : "http",
                     h->host, h->port, h->path,
                     event ? " (event: " : "",
                     event ? event : "");
        if (event) n += snprintf(buf + n, sizeof(buf) - (size_t)n, ")\n");
        else        n += snprintf(buf + n, sizeof(buf) - (size_t)n, "\n");
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/webhook/functions/unregister") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        webhook_t *h = find_hook(name);
        if (!h) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }
        h->active = 0;
        core->event_emit(core, "/events/webhook/unregister", name, strlen(name));
        portal_resp_set_status(resp, PORTAL_OK);
        n = snprintf(buf, sizeof(buf), "Hook '%s' unregistered\n", name);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/webhook/functions/send") == 0) {
        const char *name = get_hdr(msg, "name");
        const char *body = msg->body ? msg->body : get_hdr(msg, "body");
        if (!name) {
            portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
            n = snprintf(buf, sizeof(buf), "Need: name header + body\n");
            portal_resp_set_body(resp, buf, (size_t)n);
            return -1;
        }
        webhook_t *h = find_hook(name);
        if (!h) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }

        webhook_job_t *job = malloc(sizeof(*job));
        if (!job) { portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR); return -1; }
        job->hook = h;
        size_t blen = body ? (msg->body ? msg->body_len : strlen(body)) : 0;
        if (blen > sizeof(job->payload) - 1) blen = sizeof(job->payload) - 1;
        if (blen > 0) memcpy(job->payload, body, blen);
        job->payload[blen] = '\0';
        job->plen = blen;
        pthread_t th;
        pthread_create(&th, NULL, webhook_send_thread, job);
        pthread_detach(th);
        n = snprintf(buf, sizeof(buf), "Sending to '%s' in background...\n", name);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    if (strcmp(msg->path, "/webhook/functions/test") == 0) {
        const char *name = get_hdr(msg, "name");
        if (!name) { portal_resp_set_status(resp, PORTAL_BAD_REQUEST); return -1; }
        webhook_t *h = find_hook(name);
        if (!h) { portal_resp_set_status(resp, PORTAL_NOT_FOUND); return -1; }

        webhook_job_t *job = malloc(sizeof(*job));
        if (!job) { portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR); return -1; }
        job->hook = h;
        job->plen = (size_t)snprintf(job->payload, sizeof(job->payload),
            "{\"test\":true,\"source\":\"portal\"}");
        pthread_t th;
        pthread_create(&th, NULL, webhook_send_thread, job);
        pthread_detach(th);
        n = snprintf(buf, sizeof(buf), "Testing '%s' in background...\n", name);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    (void)core;
    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
