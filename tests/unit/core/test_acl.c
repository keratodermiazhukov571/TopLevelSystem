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
 * test_acl — Unit tests for Portal label-based access control
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "portal/portal.h"
#include "../src/core/core_path.h"

/* --- Label tests --- */

static void test_labels_add_and_has(void)
{
    printf("test_labels_add_and_has... ");
    portal_labels_t ls = {0};

    assert(portal_labels_add(&ls, "admin") == 0);
    assert(portal_labels_add(&ls, "finance") == 0);
    assert(ls.count == 2);

    assert(portal_labels_has(&ls, "admin") == 1);
    assert(portal_labels_has(&ls, "finance") == 1);
    assert(portal_labels_has(&ls, "hr") == 0);

    /* Duplicate add is idempotent */
    assert(portal_labels_add(&ls, "admin") == 0);
    assert(ls.count == 2);

    printf("OK\n");
}

static void test_labels_remove(void)
{
    printf("test_labels_remove... ");
    portal_labels_t ls = {0};

    portal_labels_add(&ls, "a");
    portal_labels_add(&ls, "b");
    portal_labels_add(&ls, "c");
    assert(ls.count == 3);

    assert(portal_labels_remove(&ls, "b") == 0);
    assert(ls.count == 2);
    assert(portal_labels_has(&ls, "b") == 0);
    assert(portal_labels_has(&ls, "a") == 1);
    assert(portal_labels_has(&ls, "c") == 1);

    /* Remove nonexistent */
    assert(portal_labels_remove(&ls, "z") == -1);

    printf("OK\n");
}

static void test_labels_intersects(void)
{
    printf("test_labels_intersects... ");
    portal_labels_t a = {0};
    portal_labels_t b = {0};

    portal_labels_add(&a, "admin");
    portal_labels_add(&a, "dev");

    portal_labels_add(&b, "finance");
    portal_labels_add(&b, "dev");

    /* "dev" is in both */
    assert(portal_labels_intersects(&a, &b) == 1);

    /* Remove the common label */
    portal_labels_remove(&b, "dev");
    assert(portal_labels_intersects(&a, &b) == 0);

    printf("OK\n");
}

static void test_labels_clear(void)
{
    printf("test_labels_clear... ");
    portal_labels_t ls = {0};

    portal_labels_add(&ls, "x");
    portal_labels_add(&ls, "y");
    assert(ls.count == 2);

    portal_labels_clear(&ls);
    assert(ls.count == 0);

    printf("OK\n");
}

/* --- ACL tests --- */

static void test_acl_open_path(void)
{
    printf("test_acl_open_path... ");
    portal_path_tree_t tree;
    portal_path_init(&tree);

    portal_path_register(&tree, "/public/info", "web");

    /* No labels on path = open to everyone, even anonymous */
    assert(portal_path_check_access(&tree, "/public/info", NULL) == 1);

    portal_ctx_t ctx = {0};
    assert(portal_path_check_access(&tree, "/public/info", &ctx) == 1);

    portal_path_destroy(&tree);
    printf("OK\n");
}

static void test_acl_labeled_path_denied(void)
{
    printf("test_acl_labeled_path_denied... ");
    portal_path_tree_t tree;
    portal_path_init(&tree);

    portal_path_register(&tree, "/secret/data", "vault");
    portal_path_add_label(&tree, "/secret/data", "admin");

    /* Anonymous = denied */
    assert(portal_path_check_access(&tree, "/secret/data", NULL) == 0);

    /* User with no matching labels = denied */
    portal_ctx_t ctx = {0};
    ctx.auth.user = "bob";
    portal_labels_add(&ctx.auth.labels, "viewer");
    assert(portal_path_check_access(&tree, "/secret/data", &ctx) == 0);

    portal_path_destroy(&tree);
    printf("OK\n");
}

static void test_acl_labeled_path_allowed(void)
{
    printf("test_acl_labeled_path_allowed... ");
    portal_path_tree_t tree;
    portal_path_init(&tree);

    portal_path_register(&tree, "/secret/data", "vault");
    portal_path_add_label(&tree, "/secret/data", "admin");
    portal_path_add_label(&tree, "/secret/data", "security");

    /* User with "admin" label = allowed */
    portal_ctx_t ctx1 = {0};
    ctx1.auth.user = "alice";
    portal_labels_add(&ctx1.auth.labels, "admin");
    assert(portal_path_check_access(&tree, "/secret/data", &ctx1) == 1);

    /* User with "security" label = allowed */
    portal_ctx_t ctx2 = {0};
    ctx2.auth.user = "charlie";
    portal_labels_add(&ctx2.auth.labels, "security");
    assert(portal_path_check_access(&tree, "/secret/data", &ctx2) == 1);

    /* User with both = allowed */
    portal_ctx_t ctx3 = {0};
    ctx3.auth.user = "dave";
    portal_labels_add(&ctx3.auth.labels, "admin");
    portal_labels_add(&ctx3.auth.labels, "security");
    assert(portal_path_check_access(&tree, "/secret/data", &ctx3) == 1);

    portal_path_destroy(&tree);
    printf("OK\n");
}

static void test_acl_root_bypasses(void)
{
    printf("test_acl_root_bypasses... ");
    portal_path_tree_t tree;
    portal_path_init(&tree);

    portal_path_register(&tree, "/secret/data", "vault");
    portal_path_add_label(&tree, "/secret/data", "topsecret");

    /* Root user with NO labels = still allowed */
    portal_ctx_t ctx = {0};
    ctx.auth.user = "root";
    assert(portal_path_check_access(&tree, "/secret/data", &ctx) == 1);

    portal_path_destroy(&tree);
    printf("OK\n");
}

static void test_acl_nonexistent_path(void)
{
    printf("test_acl_nonexistent_path... ");
    portal_path_tree_t tree;
    portal_path_init(&tree);

    /* Path not registered = no access */
    portal_ctx_t ctx = {0};
    ctx.auth.user = "root";
    assert(portal_path_check_access(&tree, "/nope", &ctx) == 0);

    portal_path_destroy(&tree);
    printf("OK\n");
}

static void test_acl_remove_label_opens(void)
{
    printf("test_acl_remove_label_opens... ");
    portal_path_tree_t tree;
    portal_path_init(&tree);

    portal_path_register(&tree, "/data", "db");
    portal_path_add_label(&tree, "/data", "restricted");

    /* Anonymous = denied */
    assert(portal_path_check_access(&tree, "/data", NULL) == 0);

    /* Remove the label → path becomes open */
    portal_path_remove_label(&tree, "/data", "restricted");
    assert(portal_path_check_access(&tree, "/data", NULL) == 1);

    portal_path_destroy(&tree);
    printf("OK\n");
}

/* --- Law 15 — portal_labels_allow tests --- */

static void test_labels_allow_null_ctx(void)
{
    printf("test_labels_allow_null_ctx... ");
    portal_labels_t row = {0};
    portal_labels_add(&row, "group-5");

    int bypass = -1;
    /* Null ctx = internal call = allowed, no bypass flag. */
    assert(portal_labels_allow(NULL, &row, &bypass) == 1);
    assert(bypass == 0);

    /* Also works when caller doesn't care about bypass flag. */
    assert(portal_labels_allow(NULL, &row, NULL) == 1);

    printf("OK\n");
}

static void test_labels_allow_root_bypass(void)
{
    printf("test_labels_allow_root_bypass... ");
    portal_ctx_t ctx = {0};
    ctx.auth.user = "root";

    portal_labels_t row = {0};
    portal_labels_add(&row, "group-5");

    int bypass = -1;
    /* Root sees anything. No bypass flag — root is the built-in, not sys.see_all. */
    assert(portal_labels_allow(&ctx, &row, &bypass) == 1);
    assert(bypass == 0);

    printf("OK\n");
}

static void test_labels_allow_sys_see_all(void)
{
    printf("test_labels_allow_sys_see_all... ");
    portal_ctx_t ctx = {0};
    ctx.auth.user = "supervisor";
    portal_labels_add(&ctx.auth.labels, "sys.see_all");

    portal_labels_t row = {0};
    portal_labels_add(&row, "group-5");
    portal_labels_add(&row, "group-19");

    int bypass = 0;
    /* sys.see_all grants access AND flags the bypass so the wrapper can audit. */
    assert(portal_labels_allow(&ctx, &row, &bypass) == 1);
    assert(bypass == 1);

    printf("OK\n");
}

static void test_labels_allow_public_row(void)
{
    printf("test_labels_allow_public_row... ");
    portal_ctx_t ctx = {0};
    ctx.auth.user = "alice";
    portal_labels_add(&ctx.auth.labels, "group-5");

    /* Row with no labels = visible to anyone. */
    portal_labels_t empty = {0};
    int bypass = -1;
    assert(portal_labels_allow(&ctx, &empty, &bypass) == 1);
    assert(bypass == 0);

    /* Null row_labels behaves identically. */
    assert(portal_labels_allow(&ctx, NULL, &bypass) == 1);
    assert(bypass == 0);

    printf("OK\n");
}

static void test_labels_allow_intersect(void)
{
    printf("test_labels_allow_intersect... ");
    portal_ctx_t ctx = {0};
    ctx.auth.user = "alice";
    portal_labels_add(&ctx.auth.labels, "group-5");
    portal_labels_add(&ctx.auth.labels, "region-north");

    /* Row tagged with one of her labels → visible. */
    portal_labels_t row = {0};
    portal_labels_add(&row, "group-5");
    portal_labels_add(&row, "group-9");
    int bypass = -1;
    assert(portal_labels_allow(&ctx, &row, &bypass) == 1);
    assert(bypass == 0);

    printf("OK\n");
}

static void test_labels_allow_no_intersect(void)
{
    printf("test_labels_allow_no_intersect... ");
    portal_ctx_t ctx = {0};
    ctx.auth.user = "alice";
    portal_labels_add(&ctx.auth.labels, "group-5");

    /* Row tagged only with labels she doesn't have → hidden. */
    portal_labels_t row = {0};
    portal_labels_add(&row, "group-9");
    portal_labels_add(&row, "group-19");
    int bypass = -1;
    assert(portal_labels_allow(&ctx, &row, &bypass) == 0);
    assert(bypass == 0);

    printf("OK\n");
}

static void test_labels_allow_ctx_no_labels(void)
{
    printf("test_labels_allow_ctx_no_labels... ");
    portal_ctx_t ctx = {0};
    ctx.auth.user = "nobody";
    /* No labels on the user. */

    /* Against a labeled row → denied. */
    portal_labels_t row = {0};
    portal_labels_add(&row, "group-5");
    assert(portal_labels_allow(&ctx, &row, NULL) == 0);

    /* Against a public row → still allowed. */
    portal_labels_t empty = {0};
    assert(portal_labels_allow(&ctx, &empty, NULL) == 1);

    printf("OK\n");
}

/* --- portal_auth_find_by_key — federation identity reconciler primitive --- */

#include "../src/core/core_auth.h"

static void test_auth_find_by_key_match(void)
{
    printf("test_auth_find_by_key_match... ");
    portal_auth_registry_t auth = {0};
    auth.user_count = 1;
    snprintf(auth.users[0].username, sizeof(auth.users[0].username),
             "dev-root-5");
    snprintf(auth.users[0].api_key, sizeof(auth.users[0].api_key),
             "3f2a91c4b87d2e06aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff0000");
    portal_labels_add(&auth.users[0].labels, "ssip5");

    auth_user_t *found = portal_auth_find_by_key(&auth, auth.users[0].api_key);
    assert(found == &auth.users[0]);
    assert(strcmp(found->username, "dev-root-5") == 0);
    assert(portal_labels_has(&found->labels, "ssip5") == 1);

    printf("OK\n");
}

static void test_auth_find_by_key_miss(void)
{
    printf("test_auth_find_by_key_miss... ");
    portal_auth_registry_t auth = {0};
    auth.user_count = 1;
    snprintf(auth.users[0].api_key, sizeof(auth.users[0].api_key),
             "aaaa1111bbbb2222cccc3333dddd4444");

    assert(portal_auth_find_by_key(&auth, "nope-not-a-real-key") == NULL);

    printf("OK\n");
}

static void test_auth_find_by_key_empty_key(void)
{
    printf("test_auth_find_by_key_empty_key... ");
    portal_auth_registry_t auth = {0};

    assert(portal_auth_find_by_key(&auth, NULL) == NULL);
    assert(portal_auth_find_by_key(&auth, "")   == NULL);
    assert(portal_auth_find_by_key(NULL, "x")   == NULL);

    printf("OK\n");
}

static void test_auth_find_by_key_ignores_empty_stored_key(void)
{
    printf("test_auth_find_by_key_ignores_empty_stored_key... ");
    portal_auth_registry_t auth = {0};
    auth.user_count = 1;
    snprintf(auth.users[0].username, sizeof(auth.users[0].username),
             "keyless");
    auth.users[0].api_key[0] = '\0';

    assert(portal_auth_find_by_key(&auth, "") == NULL);
    assert(portal_auth_find_by_key(&auth, "some-key") == NULL);

    printf("OK\n");
}

int main(void)
{
    printf("=== Portal ACL Tests ===\n\n");

    /* Label tests */
    test_labels_add_and_has();
    test_labels_remove();
    test_labels_intersects();
    test_labels_clear();

    /* ACL tests */
    test_acl_open_path();
    test_acl_labeled_path_denied();
    test_acl_labeled_path_allowed();
    test_acl_root_bypasses();
    test_acl_nonexistent_path();
    test_acl_remove_label_opens();

    /* Law 15 — portal_labels_allow */
    test_labels_allow_null_ctx();
    test_labels_allow_root_bypass();
    test_labels_allow_sys_see_all();
    test_labels_allow_public_row();
    test_labels_allow_intersect();
    test_labels_allow_no_intersect();
    test_labels_allow_ctx_no_labels();

    /* Federation reconciler primitive — portal_auth_find_by_key */
    test_auth_find_by_key_match();
    test_auth_find_by_key_miss();
    test_auth_find_by_key_empty_key();
    test_auth_find_by_key_ignores_empty_stored_key();

    printf("\nAll tests passed.\n");
    return 0;
}
