<!--
  Author: Germán Luis Aracil Boned <garacilb@gmail.com>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, see <https://www.gnu.org/licenses/>.
-->

# Portal — Coding rules

Write less. Check everything. Fail closed.

These are the hard rules for every line of C in this repo. They sit
alongside [`PHILOSOPHY.md`](PHILOSOPHY.md) (the 15 Laws of God —
architecture) and [`SECURITY.md`](SECURITY.md) (the trust model). This
file is the **coding** layer: how to write individual functions so
they are safe, readable, and the next session doesn't have to audit
them again.

---

## 1. Never hand user data to a shell

**Don't**

```c
snprintf(cmd, sizeof(cmd), "tar czf '%s' -C / '%s'", fpath, source);
popen(cmd, "r");

snprintf(cmd, sizeof(cmd), "ssh-keygen -f %s", g_host_key);
system(cmd);
```

A single `'` in `source` or `g_host_key` breaks quoting and gives an
attacker the process's privileges.

**Do**

```c
pid_t pid = fork();
if (pid == 0) {
    char *const argv[] = {
        "tar", "czf", fpath, "-C", "/", source, NULL
    };
    execvp("tar", argv);
    _exit(127);
}
int status;
waitpid(pid, &status, 0);
```

`execvp` takes argv as an array — no shell, no quoting, no injection.
If you need the output, `pipe()` before fork and read from the child's
stdout in the parent.

**Only exception**: shell is unavoidable AND every interpolated value
is a constant at compile time (e.g. `system("sync")`). User-influenced
strings — headers, config values, PG rows — **never** land in a shell.

---

## 2. Bounded string building

**Don't**

```c
char groups[1024] = {0};
for (int i = 0; i < u->labels.count; i++) {
    if (i > 0) strcat(groups, ",");
    strcat(groups, u->labels.labels[i]);
}
```

`PORTAL_MAX_LABELS × PORTAL_MAX_LABEL_LEN = 32 × 64 = 2048 bytes`.
A user with max labels overflows the 1024-byte buffer — stack smash.

**Do**

```c
char groups[1024] = {0};
size_t off = 0;
for (int i = 0; i < u->labels.count && off < sizeof(groups) - 1; i++) {
    int n = snprintf(groups + off, sizeof(groups) - off,
                     "%s%s", i > 0 ? "," : "", u->labels.labels[i]);
    if (n < 0 || (size_t)n >= sizeof(groups) - off) break;
    off += (size_t)n;
}
```

Always pass `sizeof(buf) - off` as the limit; always check the return
value against the remaining space; always cap the loop by the buffer.

**Rule of thumb**: every `strcat` / `strcpy` in new code is a bug.
Use `snprintf` tracking `off`.

---

## 3. Fail closed on entropy

**Don't**

```c
FILE *f = fopen("/dev/urandom", "rb");
if (f) { ... }
else {
    srand(time(NULL));     /* predictable seed */
    for (i < len) buf[i] = rand() % 16;
}
```

Any attacker who knows the boot time reproduces the token.

**Do**

```c
#include <sys/random.h>

unsigned char raw[AUTH_KEY_LEN / 2];
if (getrandom(raw, sizeof(raw), 0) != (ssize_t)sizeof(raw)) {
    /* No usable CSPRNG — treat as unrecoverable. */
    return -1;
}
static const char hex[] = "0123456789abcdef";
for (size_t i = 0; i < sizeof(raw); i++) {
    buf[2*i]     = hex[raw[i] >> 4];
    buf[2*i + 1] = hex[raw[i] & 0xf];
}
buf[AUTH_KEY_LEN] = '\0';
```

Two bytes per byte-of-input means no wasted entropy. No `rand()`
anywhere in security-sensitive paths — ever.

---

## 4. Never ship a default privileged credential

**Don't**

```c
portal_auth_add_user(auth, "root", "", &root_labels);  /* empty pw */
```

Fresh deploys have `login root ""` that works until an operator
remembers to run `passwd`.

**Do**

- At first boot, generate a random password, write it once to a
  mode-0600 file in the instance dir, log its location (not the
  value) to stderr, and require the operator to read it.
- Or require `--set-root-password` on instance creation; refuse to
  start without one.
- Or gate all auth-requiring paths behind a "setup not complete"
  flag that only a locally-reachable endpoint can clear.

Whatever you pick: **never** leave an enabled account with a known
or empty password in a binary that might land on a network.

---

## 5. Input validation belongs at the boundary

HTTP headers, CLI arguments, federation message headers, PG column
values — all **untrusted**. Validate once, at the point where the
untrusted world ends and internal code begins. After that, treat the
value as structured data.

**Pattern**:

```c
static int parse_device_id(const char *s, int *out)
{
    if (!s || !s[0]) return -1;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (end == s || *end != '\0') return -1;
    if (v < 1 || v > INT_MAX) return -1;
    *out = (int)v;
    return 0;
}

/* in handler: */
int device_id;
if (parse_device_id(get_hdr(msg, "deviceid"), &device_id) < 0) {
    portal_resp_set_status(resp, PORTAL_BAD_REQUEST);
    return -1;
}
```

Same for paths (canonicalize + allowlist prefix), URLs (parse + check
scheme + host allowlist), regex matches (anchored), etc.

---

## 6. Label checks are cheap — use them

Every new `core->path_register` for a mutating operation should be
followed by:

```c
core->path_set_access(core, path, PORTAL_ACCESS_RW);
core->path_add_label(core, path, "hub-admin");   /* or "admin" */
```

Never assume "only an operator will call this". The dispatcher's
Law 8 gate (`portal_path_check_access`) is the one line that keeps
anonymous federation peers out. Missing a label = silently open to
anyone who can reach the socket.

If a path genuinely must be open (e.g. device register without
existing creds), it should have a **header-level auth check in the
handler** (128-hex password, magic-link, etc.) that's explicit and
auditable.

---

## 7. Trust federation identity, not self-declared identity

**Don't**

```c
/* message claims to come from admin — trust it */
if (msg->ctx && msg->ctx->auth.user &&
    strcmp(msg->ctx->auth.user, "admin") == 0) { allow = 1; }
```

On inbound federation paths, `ctx->auth.user` is already the peer's
resolved local identity (set by `mod_node` from the handshake-time
`identity_proof` exchange). Checking the username works. But don't
re-read untrusted headers ("X-User:" etc.) and trust them over
`ctx`.

**Do**: always read identity from `msg->ctx->auth.user` and
`msg->ctx->auth.labels`. Those are the fields the core populates
from the authenticated session or federation handshake.

---

## 8. Crash locally, degrade globally

Portal catches `SIGSEGV` / `SIGBUS` in module handlers via
`sigsetjmp` in the dispatcher. A module crash returns
`500 Module crashed` to the caller; the core keeps running. Use
that — don't try to do defensive NULL checks "just in case":

**Don't**

```c
void *p = maybe_null();
if (!p) { /* log and silently return — caller thinks it worked */ }
```

**Do**

```c
void *p = maybe_null();
assert(p);                   /* in development */
if (!p) {
    portal_resp_set_status(resp, PORTAL_INTERNAL_ERROR);
    portal_resp_set_body(resp, "internal: null ptr\n", 19);
    return -1;
}
```

Silent success on a bug is worse than a caught crash.

---

## 9. One error path, obvious cleanup

**Don't** (nested cleanup after every failure branch):

```c
void *a = malloc(...);
if (!a) return -1;
void *b = malloc(...);
if (!b) { free(a); return -1; }
void *c = malloc(...);
if (!c) { free(b); free(a); return -1; }
```

**Do** (single label, `goto fail`):

```c
void *a = NULL, *b = NULL, *c = NULL;
int rc = -1;
a = malloc(...); if (!a) goto fail;
b = malloc(...); if (!b) goto fail;
c = malloc(...); if (!c) goto fail;
rc = 0;
fail:
    free(c); free(b); free(a);
    return rc;
```

The Linux-kernel `goto fail` pattern. Reviewers verify the cleanup
order once, not per branch.

---

## 10. Comments earn their keep

Most comments are noise. A comment is worth writing when it:
- explains a **non-obvious invariant** (`* path[0] is always '/'`)
- warns about a **trap** (`* don't free — owned by the path table`)
- justifies a **counter-intuitive choice** (`* snprintf is correct — we want truncation on oversize`)

Don't write:
- `/* increment x */ x++;`
- `/* loop over labels */ for (...)`
- `/* return result */ return rc;`
- Author names or dates. `git log` already tracks that.

---

## 11. Lock the event loop sparingly

Portal's main thread runs libev. If a handler calls `core->send`, it
must be on the main thread (there's a memory entry about this). Any
thread-pool worker that wants to call `core->send` has to queue the
message to the main thread via `core->timer_add` or a `pipe()` the
main thread watches.

Don't do I/O in a `timer_add` callback either — the callback runs on
the main thread too. Offload to a `pthread_create` + detach, or use
`mod_worker` which already manages a pool.

---

## 12. Test the boundary, not the internals

Per-module unit tests live in `tests/unit/modules/`. Write them for
the public path behavior (what arrives → what comes back), not
internal struct shapes. When internals change you want tests to still
pass; when the API contract changes you want them to scream.

Integration tests (`tests/integration/test_complete.py`) cover the
full dispatch chain — 229 tests today. Every new public path should
get at least one integration test confirming it's reachable, ACL
works, and bad inputs return the right status.

---

## 13. Build warnings are bugs

`CFLAGS` includes `-Wall -Wextra -Werror -std=c11`. A warning means
the build breaks. Don't suppress with `(void)` casts or disabled
flags — fix the code:

- `unused-parameter` → `(void)param` only for interface functions you
  can't change.
- `sign-compare` → pick one type (size_t) and use it consistently.
- `format-security` → use literal format strings; never pass
  user input as the first arg to `printf`/`snprintf`.

---

## 14. Read before you write

Before changing a file, read enough context to know:
- what module / subsystem does it belong to,
- what invariants it's maintaining (see its module comment header),
- who calls it and from what thread,
- does the path have label gates and who passes them.

Five minutes of reading saves five hours of regression hunting.

---

## 15. Commit messages are the audit log

Commit messages should answer "why this change" in 2-3 sentences.
The "what" is in the diff. Example:

```
fix(shell): reject DIRECT-mode connections on hubs

The dial-back listener accepted a "DIRECT <rows> <cols>" line and
ran /bin/su immediately with no Portal auth — any peer that reached
:2223 over TLS got a login prompt. shell_disable_direct_target=true
in mod_shell.conf now rejects DIRECT entirely; dial-back via
session_id still works because that path requires a pre-registered
pending_shell entry.
```

Don't write:
- `Update mod_shell.c` (what's in the diff)
- `Fix bug` (which bug?)
- "Various fixes" (squashing unrelated work is a review hazard)

One logical change per commit. One blame-worthy commit per bug.

---

## See also

- [`PHILOSOPHY.md`](PHILOSOPHY.md) — 15 Laws of God: the architecture these rules implement.
- [`SECURITY.md`](SECURITY.md) — the trust model every handler enforces.
- [`MODULE_GUIDE.md`](MODULE_GUIDE.md) — how to build a new module from zero.
- [`CORE_API.md`](CORE_API.md) — the ABI surface these rules constrain.
