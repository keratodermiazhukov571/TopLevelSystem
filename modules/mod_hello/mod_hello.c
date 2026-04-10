/*
 * mod_hello — Example module for Portal
 *
 * Simple hello world module to demonstrate module development.
 * Accessible via CLI: get /hello/resources/greeting
 * Accessible via HTTP: http://host:8080/api/hello/resources/greeting
 */

#include <stdio.h>
#include <string.h>
#include "portal/portal.h"

static portal_module_info_t info = {
    .name        = "hello",
    .version     = "1.0.0",
    .description = "Hello world example module",
    .soft_deps   = NULL
};

portal_module_info_t *portal_module_info(void) { return &info; }

int portal_module_load(portal_core_t *core)
{
    core->path_register(core, "/hello/resources/greeting", "hello");
    core->path_set_access(core, "/hello/resources/greeting", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/hello/resources/greeting", "Hello world greeting message");
    core->path_register(core, "/hello/resources/time", "hello");
    core->path_set_access(core, "/hello/resources/time", PORTAL_ACCESS_READ);
    core->path_set_description(core, "/hello/resources/time", "Message counter (increments per request)");
    core->log(core, PORTAL_LOG_INFO, "hello", "Hello module loaded");
    return PORTAL_MODULE_OK;
}

int portal_module_unload(portal_core_t *core)
{
    core->path_unregister(core, "/hello/resources/greeting");
    core->path_unregister(core, "/hello/resources/time");
    core->log(core, PORTAL_LOG_INFO, "hello", "Hello module unloaded");
    return PORTAL_MODULE_OK;
}

int portal_module_handle(portal_core_t *core, const portal_msg_t *msg,
                          portal_resp_t *resp)
{
    (void)core;

    if (strcmp(msg->path, "/hello/resources/greeting") == 0) {
        const char *text = "Hello from Portal! Welcome to the universal modular core.\n";
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, text, strlen(text));
        return 0;
    }

    if (strcmp(msg->path, "/hello/resources/time") == 0) {
        char buf[128];
        int n = snprintf(buf, sizeof(buf), "Portal is running. Message #%lu\n", msg->id);
        portal_resp_set_status(resp, PORTAL_OK);
        portal_resp_set_body(resp, buf, (size_t)n);
        return 0;
    }

    portal_resp_set_status(resp, PORTAL_NOT_FOUND);
    return -1;
}
