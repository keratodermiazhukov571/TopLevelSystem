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
 * core_path.h — Path registry with hash table lookup and label-based ACL
 */

#ifndef CORE_PATH_H
#define CORE_PATH_H

#include "portal/types.h"
#include "core_hashtable.h"

/* A registered path entry */
typedef struct {
    char             path[PORTAL_MAX_PATH_LEN];
    char             module_name[PORTAL_MAX_MODULE_NAME];
    portal_labels_t  labels;
    uint8_t          access_mode;   /* PORTAL_ACCESS_READ/WRITE/RW (Law 8) */
    char             description[256]; /* Human-readable description for help system */
} path_entry_t;

/* Path registry — hash table for O(1) lookups */
typedef struct {
    portal_ht_t  table;     /* key: path string, value: path_entry_t* */
    int          count;
} portal_path_tree_t;

void portal_path_init(portal_path_tree_t *tree);
void portal_path_destroy(portal_path_tree_t *tree);

/* Register a path → module mapping. Returns 0 on success. */
int  portal_path_register(portal_path_tree_t *tree, const char *path,
                           const char *module_name);

/* Unregister a path. Returns 0 on success. */
int  portal_path_unregister(portal_path_tree_t *tree, const char *path);

/* Lookup which module handles a path. Returns module name or NULL. */
const char *portal_path_lookup(portal_path_tree_t *tree, const char *path);

/* Lookup the full path entry. Returns NULL if not found. */
path_entry_t *portal_path_lookup_entry(portal_path_tree_t *tree, const char *path);

/* Set labels on a path. Returns 0 on success. */
int  portal_path_set_labels(portal_path_tree_t *tree, const char *path,
                             const portal_labels_t *labels);

/* Add a single label to a path. Returns 0 on success. */
int  portal_path_add_label(portal_path_tree_t *tree, const char *path,
                            const char *label);

/* Remove a label from a path. Returns 0 on success. */
int  portal_path_remove_label(portal_path_tree_t *tree, const char *path,
                               const char *label);

/* Set description on a path. Returns 0 on success. */
int  portal_path_set_description(portal_path_tree_t *tree, const char *path,
                                  const char *description);

/* Get labels for a path. Returns pointer to labels or NULL. */
const portal_labels_t *portal_path_get_labels(portal_path_tree_t *tree,
                                               const char *path);

/*
 * Check if a user context has access to a path.
 * Rules:
 *   - root user → always allowed
 *   - path has no labels → open (anyone can access)
 *   - path has labels → user must have at least one matching label
 * Returns 1 if allowed, 0 if denied.
 */
int  portal_path_check_access(portal_path_tree_t *tree, const char *path,
                               const portal_ctx_t *ctx);

/*
 * Law 15 — group-scoped output filter predicate.
 *
 * Decide whether a row bearing row_labels should be visible to ctx.
 * This is the companion to portal_path_check_access: that one gates
 * "can you call this path?", this one filters "which rows do you see?".
 *
 * Rules applied in order (short-circuit on first match):
 *   1. ctx is NULL                                → allowed (internal call).
 *   2. ctx->auth.user == "root"                   → allowed.
 *   3. ctx->auth.labels has "sys.see_all"         → allowed, and *bypass
 *                                                   is set to 1 so the caller
 *                                                   can emit an audit event.
 *   4. row_labels is NULL or row_labels->count==0 → allowed (public row).
 *   5. otherwise                                   → intersection check.
 *
 * The `bypass` output is optional (may be NULL). It exists so the core
 * API wrapper can emit /events/acl/bypass without requiring this pure
 * predicate to depend on the event registry.
 *
 * Returns 1 if allowed, 0 if denied.
 */
int  portal_labels_allow(const portal_ctx_t *ctx,
                          const portal_labels_t *row_labels,
                          int *bypass);

/* List all registered paths. Calls callback for each. */
typedef void (*portal_path_list_fn)(const char *path, const char *module_name,
                                     void *userdata);
void portal_path_list(portal_path_tree_t *tree, portal_path_list_fn callback,
                       void *userdata);

#endif /* CORE_PATH_H */
