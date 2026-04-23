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

# Portal Security

The single source of truth for how Portal's security model works, every
knob it exposes, and what an operator does to manage it. Reading this
once should leave you able to provision users, lock down paths, scope
operator visibility, federate two nodes, and reason about what the
system does and does not protect against.

When you find this doc out of sync with the code, the code wins —
update this doc, don't reverse it. (Law 1, Law 5.)

---

## 1. The model in one paragraph

Portal has **one identity model** and **one authorization model**, and
both apply uniformly to every interface — local CLI, HTTP/HTTPS REST,
SSH, and federation between nodes.

- **Identity** is a Portal user record (username + password + api_key
  + labels). A caller proves identity by presenting a password, a
  session token from `/auth/login`, or an api_key. On federation
  the proof rides as the api_key in `ctx->auth.token` and is
  re-authenticated against the *receiving* node's local registry — no
  cross-node trust, no shared session table.
- **Authorization** is a label intersection: every resource path
  carries zero or more labels, every user carries zero or more labels;
  if either side is empty, access is open; otherwise the user must
  carry at least one of the path's labels (Law 8). A second filter
  drops emitted *rows* whose own labels don't intersect the caller's
  (Law 15). User `root` and the `sys.see_all` label bypass both
  layers — the bypass is audited.

Everything below is detail.

---

## 2. Identity

### 2.1 User record

Defined in `include/portal/types.h` and `src/core/core_auth.h`:

```c
typedef struct {
    char            username[PORTAL_MAX_LABEL_LEN];   /* unique */
    char            password[256];                    /* "$sha256$salt$hash" or plain */
    char            api_key[AUTH_KEY_LEN + 1];        /* 64 hex chars */
    portal_labels_t labels;                           /* up to PORTAL_MAX_LABELS */
} auth_user_t;
```

There is no separate "group" object — a group is just a label that one
or more users carry. `/groups/<n>/add` adds the label `<n>` to the
user; `/groups/<n>/remove` strips it.

### 2.2 The three authentication methods

| Method | Credential | Carried as | Where you'd use it |
|---|---|---|---|
| Password | `username` + `password` | `POST /auth/login` returns a session token | Interactive logins, web forms |
| Session token | 64-hex returned by `/auth/login` | `Authorization: Bearer …` or `X-Auth-Token: …` | Browser sessions, scripted calls after login |
| API key | 64-hex per user, lifetime = user record | `X-API-Key: …` header (HTTP), `ctx->auth.token` (federation) | Service-to-service, federation peer identity |

API keys are first-class — every user has one, generated on creation
or rotation. Issue: `/auth/key/rotate?user=<n>`. Read: `/auth/key`
(returns the calling user's own key only).

### 2.3 Where users come from

- **Default seed** — `users.conf` next to `portal.conf` lists initial
  users. Format: `username:password:label1,label2:api_key`. `api_key`
  may be `auto` (generated on first start) or empty (generated on first
  use). Per-instance file lives at `/etc/portal/<inst>/users.conf`.
- **Runtime create** — `PUT /users/<name>` with `password` + `groups`
  headers. Persisted to the storage backend (sqlite or psql) and the
  KV store. **Admin-only** since Phase 3 (see §6.2).
- **Module auto-provisioning** — modules with a need (e.g. mod_ssip_hub
  creating per-carrier `dev-root-<N>` users) call
  `core->auth_ensure_user(core, username, labels, key, …)`. The
  `key` argument is NULL for "generate random" or a string for "use
  this exact api_key". Persists through the same dual-write path. See
  §6 for the full API.

Two reserved usernames exist by default: `root` (full bypass at the
ACL layer) and `admin` (no bypass, but seeded with the `admin` label).

---

## 3. Authorization (Law 8 — path ACL)

Every path registered with `core->path_register(core, path, module)`
gets:

- An **access mode** — `PORTAL_ACCESS_READ`, `WRITE`, or `RW` — set via
  `core->path_set_access`. Currently informational (used by
  documentation generators and the CLI help), not enforced at dispatch.
- Zero or more **labels** — added via `core->path_add_label`.

At dispatch time, `portal_path_check_access` (`src/core/core_path.c:128`)
runs:

1. Path not in registry → deny.
2. Caller is user `root` → allow (the only username-based bypass).
3. Path has no labels → allow.
4. Caller has no context or no user → deny.
5. Otherwise → `portal_labels_intersects(path.labels, caller.labels)`.

Match the rules in your head before adding a label, because they
short-circuit in this order.

### 3.1 Reserved label vocabulary

These labels have agreed meaning across the system. Anything else is
free for module/operator use.

| Label | Carried by | Meaning |
|---|---|---|
| `root` | (paths) the default `mod_shell.access_label`; unrelated to the *user* `root` which bypasses regardless | Required to call `/shell/functions/*` unless the caller is user `root` |
| `admin` | seeded `admin` user | Generic admin gate; modules that want a single admin label use this |
| `hub-admin` | hub operators (Phase 3) | Required to call mutation endpoints `/users/`, `/groups/`, `/core/modules/`, `/core/config/set` |
| `hub-operator` | hub operators (recommended convention) | Read-only operator access; not currently enforced by core |
| `sys.see_all` | supervisors | Bypasses Law 15 row filtering (audited via `/events/acl/bypass`) |
| `ssip-device` | per-carrier `dev-root-<N>` user | Marks "this caller is a federated SSIP device, not an operator" |
| `ssip<N>` | per-carrier `dev-root-<N>` user AND operators of carrier N | Carrier scope for the SSIP fleet (Law 15 filter on the updates dashboard, plus any other label-keyed policy) |

If you invent a new label, document it here.

---

## 4. Output filtering (Law 15)

Where Law 8 asks "can you call this path?", Law 15 asks "of the rows
this path returns, which ones do you see?". Both checks fire; either
can deny.

### 4.1 The predicate

`core->labels_allow(core, ctx, row_labels)` (`include/portal/core.h`,
backed by `portal_labels_allow` in `core_path.c`):

1. `ctx == NULL` → allow (internal call).
2. `ctx->auth.user == "root"` → allow (no bypass event — root is the
   built-in).
3. `ctx` has label `sys.see_all` → allow AND emit
   `/events/acl/bypass` with body `user=<name>`.
4. `row_labels` is NULL or empty → allow (public row).
5. Otherwise → label intersection.

### 4.2 Module idiom

Any handler that lists rows: `if (!core->labels_allow(core, msg->ctx,
&row_labels)) continue;` See `mod_node.c:/node/resources/peers` for
the worked example or `docs/MODULE_GUIDE.md` §"Filtering row output".

### 4.3 Detail lookups never leak existence

If a caller asks for a specific row by name (a detail handler, not a
list), and the filter denies, the response is **the same "not found"**
the handler would return for a row that genuinely doesn't exist.
Distinguishing "hidden" from "absent" turns the filter into an
enumeration sidechannel — don't.

---

## 5. Federation identity (always on as of Phase 5, 2026-04-19)

Portal nodes peer over TLS-PORTAL02 (mod_node). Once the handshake
completes, the two peers run a small bidirectional **identity_proof**
exchange that resolves each side's claimed key against the other
side's local user registry. Subsequent inbound messages from that
peer are dispatched as the resolved local user (or anonymous if no
key matched). The legacy "promote every federated message to local
root" compat path was removed in Phase 5.

### 5.1 Wire flow

1. Initiator's `mod_node`, post-handshake, sends `CALL
   /<peer>/node/functions/identity_proof` with header `key=<our
   outbound key for this peer>`.
2. Responder's handler validates the key via `core->auth_find_by_key`.
   On match, stores the resolved user (name + labels) on the peer
   struct and replies 200 with **its** outbound key for the same peer
   in the response body. On miss, returns 401 with no body —
   strict initiator-first ordering ensures we don't reveal our key to
   a stranger.
3. Initiator validates the body the same way and stores the result.
4. From this point, the per-peer state drives `ctx->auth` for every
   inbound message. No further key exchange occurs on that connection.

### 5.2 Configuration (`mod_node.conf`)

```
federation_key  = <shared secret>     # mesh membership only
peer_default_key = <hex>              # OUR outbound key for any unlisted peer
peer_keys        = <peer1>:<hex>, <peer2>:<hex>
```

- `federation_key` gates **mesh membership** at the PORTAL02
  handshake. Knowing it grants **no** user-level privileges.
- `peer_keys` is the per-peer outbound key map. Each `<hex>` must
  match the api_key of a Portal user on the destination node.
- `peer_default_key` is the fallback used for any peer not in
  `peer_keys`. For multi-tenant deployments **leave it empty** so a
  compromise of one peer's key reveals only that peer's identity.
- A **runtime** mutation API exists at `/node/functions/set_peer_key`
  (admin-or-internal gated) so modules like `mod_ssip_hub` can
  populate keys without restart.
- `federation_inbound_default_user = <username>` — opt-in escape
  hatch added 2026-04-19. When set, an inbound federation peer that
  did **not** complete identity_proof (anonymous from our perspective)
  is stamped as this local user instead of NULL. The user must exist
  locally; its labels are cached at module load. **Never set on
  multi-peer nodes** — any peer that knows `federation_key` would
  inherit this user's privileges. Designed for SSIP devices: a single
  trusted peer (the hub), and `peer_keys`-based identity is hard to
  bootstrap on dev boxes (`root = 0` has no carrier-bot) or after
  truncation effects (`api_key` field is 64 hex but `/etc/ssippwd` is
  128 hex SHA-512). On a device, `federation_inbound_default_user =
  hub` makes operator shell from the hub work even when identity
  exchange degrades. Hub-side stays strict.

### 5.3 Anonymous semantics

Inbound from a peer with no matching key in our registry → ctx is
cleared (user NULL, no labels). Downstream Law 8 denies labeled
paths; Law 15 denies labeled rows. The peer is alive on the wire but
useful only for explicitly open endpoints.

### 5.4 Migration support

For SSIP devices that registered before Phase 2a shipped: the hub
exposes `/ssip/hub/functions/get_carrier_key` (auth: device's existing
128-hex `password` header). On boot, `mod_ssip` notices the missing
`peer_keys` line, calls the endpoint, writes the key, `_exit(0)`s for
systemd to respawn portal. Idempotent across reboots, silent skip on
older hubs (404).

### 5.5 What this defends and what it doesn't

- **Defends**: a compromised federation peer key can no longer be
  used as a master key to act as root on every other peer. Each peer
  is locally bounded to whatever identity its key resolves to, and
  the Phase 3 gate (§6.2) prevents low-priv identities from mutating
  anything.
- **Doesn't defend**: a peer that knows the **shared `federation_key`**
  can still complete the PORTAL02 handshake and JOIN the mesh.
  Identity exchange comes after; without provisioned `peer_keys` an
  attacker on the mesh just becomes anonymous to everyone — annoying
  but bounded. Treat the `federation_key` as "you can talk to us at
  all"; treat per-peer keys as identity.

---

## 6. The mutation gate (Phase 3)

Several core paths are dispatched via the prefix router and were
historically not registered in the path tree with labels — the Law 8
ACL silently skipped them. This was harmless under the legacy compat
"promote to root" path, but under strict identity a low-privilege
federation peer could otherwise mutate users, groups, modules, or
config because it would still pass the empty-label check.

`core_handlers.c:caller_is_admin()` closes the gap explicitly:

- User `root` → allow.
- Caller has label `hub-admin` → allow.
- Otherwise → 403 FORBIDDEN.

### 6.1 Gated endpoints (admin-only)

| Path | Method | Notes |
|---|---|---|
| `/users/<name>` | SET | Create/update user |
| `/users/<name>/password` | CALL | **Self-exception**: the user themselves can change their own password without `hub-admin` |
| `/groups/<name>` | SET | Create group |
| `/groups/<name>/add` | CALL | Add user to group |
| `/groups/<name>/remove` | CALL | Remove user from group |
| `/core/modules/<name>` | CALL | Load/unload/reload module |
| `/core/config/set` | (any) | Mutate any module config value |
| `/ssip/functions/set_hub_key` (devices) | CALL | Hub-pushed re-key on root reassignment. Auth: caller's resolved local user must be `hub` (Phase 2b). The `hub-admin` label on the path is belt-and-braces — both must hold. |

### 6.2 Read endpoints stay open

`GET /users`, `GET /users/<n>`, `GET /groups`, `GET /groups/<n>`,
`GET /core/config/get`, `GET /core/modules`, `GET /core/paths` —
any authenticated caller. Anonymous callers (federation peers without
a matching key) still cannot reach them in practice because the
prefix router falls through to deny if the dispatch handler doesn't
know what to do, but if you want explicit denial for anonymous
callers, label the relevant paths.

### 6.3 Module-API helpers

```c
int (*auth_find_by_key)(portal_core_t *core, const char *api_key,
                        char *out_username, size_t out_username_sz,
                        portal_labels_t *out_labels);
int (*auth_find_user)(portal_core_t *core, const char *username,
                      portal_labels_t *out_labels);
int (*auth_ensure_user)(portal_core_t *core,
                        const char *username,
                        const portal_labels_t *labels,
                        const char *key,
                        char *out_key, size_t out_key_sz);
int (*labels_allow)(portal_core_t *core,
                    const portal_ctx_t *ctx,
                    const portal_labels_t *row_labels);
```

All in `include/portal/core.h`. Pure reads except `auth_ensure_user`,
which dual-writes (storage + KV).

---

## 7. Encryption

### 7.1 Federation TLS (`mod_node`)

Per-instance settings in `[mod_node]`:

```
tls         = true|false        # required for federation in production
cert_file   = /etc/portal/<inst>/certs/server.crt
key_file    = /etc/portal/<inst>/certs/server.key
tls_verify  = true|false        # require valid peer cert chain
```

The default `tls_verify = false` accepts self-signed certs — useful in
small meshes; **flip to `true` in production** where you have a CA. The
identity exchange (§5) is entirely independent of this — both layers
should be on.

### 7.2 HTTPS (`mod_web`)

```
[mod_web]
port      = 8080      # plain HTTP; set 0 to disable
tls_port  = 8443      # HTTPS; set 0 to disable
cert_file = …
key_file  = …
```

When both are non-zero, both listen. Clients should use HTTPS. The
plain HTTP port is acceptable for in-cluster localhost-only
deployments; anywhere else, set `port = 0`.

### 7.3 SSH (`mod_ssh`)

```
[mod_ssh]
port     = 2220 + (web_port - 8080)        # auto-derived per instance
host_key = /etc/portal/<inst>/certs/ssh_host_key
```

mod_ssh accepts username + password (no key-based auth at present).
Authenticated session is bridged to the local `mod_cli` socket — same
ACL as a direct CLI session.

> **Known issue (HIGH severity, audit findings open)** — `mod_ssh`'s
> host-key generation calls `system("ssh-keygen ... -f %s ...",
> g_host_key)` where `g_host_key` is config-controlled. Unsanitised
> path with shell metacharacters → command injection. Track in
> security debt; do not set `host_key` from untrusted config.

---

## 8. Audit (`mod_audit`)

`mod_audit` records every request and every event-system emission to a
circular in-memory buffer (default 10 000 entries) and optionally
appends to a log file (`audit_file = path` in `mod_audit.conf`). The
file is opened in append mode but is **plaintext and clearable** by
anyone with the `admin` label via `/audit/functions/clear`.

`/events/acl/bypass` (emitted by Law 15's `sys.see_all` rule) is one
of the events recorded. Other auth-relevant events:

- `/events/auth/login` (login success/failure — emitted by `core_auth`)
- `/events/auth/key_rotated` (api_key regeneration)
- Module-specific: `/events/ssip/hub/register_approved`, etc.

### 8.1 Known limits

- Not tamper-evident — no HMAC chain.
- Not rotated automatically (operator manages logrotate).
- The federation identity exchange itself does NOT yet emit an audit
  event. (Tracked as small follow-up dev work; see §13.)

---

## 9. Operator runbooks

### 9.1 Create an operator (e.g. Maria for SSIP root 5)

```bash
# On the hub, attach to CLI as root
portal -n hub -r
portal:/> login root <root password>

# Create the user with an initial password
portal:/> user create maria <s3cretpass>

# Grant carrier visibility (Law 15 scopes the SSIP updates dashboard)
portal:/> group adduser ssip5 maria

# Grant operator role (currently informational; reserved for future use)
portal:/> group adduser hub-operator maria

# If she also needs to mutate users/groups/modules/config:
portal:/> group adduser hub-admin maria
```

Maria can now log in to the hub via HTTP/CLI/SSH with her password,
see only root-5 device updates, and (if granted `hub-admin`) create
more users.

### 9.2 Create a supervisor (sees everything)

```bash
portal:/> user create supervisor <s3cretpass>
portal:/> group adduser sys.see_all supervisor
portal:/> group adduser hub-admin supervisor
```

Every Law 15 row this user inspects emits `/events/acl/bypass` —
visible in `mod_audit`'s log + queryable via `get
/audit/resources/log`. Use sparingly.

### 9.3 Rotate a user's API key

```bash
# Via CLI (the rotated user receives the new key once; cannot re-fetch)
portal:/> key <username>

# Via HTTP (admin only)
curl -X CALL -H "X-Auth-Token: $ADMIN_TOK" \
  http://host:8080/api/auth/key/rotate?user=<username>
```

If the rotated user is one referenced by another node's `peer_keys`,
that peer's `mod_node.conf` must be updated and `mod_node` must be
re-init'd or the runtime API `/node/functions/set_peer_key` called.

### 9.4 Federate two new nodes

On each side:

1. Pick a unique `node_name` and a shared `federation_key` (paste the
   same hex in both `mod_node.conf` files).
2. Configure the dialer side's peer entry in the `[nodes]` section:
   `peer0 = <other-name>=<host>:<port>`.
3. Create a Portal user on each node that the other side will
   authenticate as (e.g. on node A create user `peer-from-B`, note
   its api_key; on node B create user `peer-from-A`, note its
   api_key).
4. On node A `mod_node.conf`: `peer_keys = B:<peer-from-A's api_key>`.
5. On node B `mod_node.conf`: `peer_keys = A:<peer-from-B's api_key>`.
6. Restart both. The log line `Identity exchange ok with peer 'X' →
   local user 'Y'` confirms success on both sides.

### 9.5 Fix a peer that arrives anonymous

Symptom: `journalctl … grep "Peer .* returned key that does not match
any local user"` or `Identity exchange with .* failed (status=401)`.

Cause: outbound `peer_keys` entry on one side doesn't match an
api_key in the other side's user registry. Re-derive the key via
`auth.key` on the destination, edit `peer_keys` on the source,
restart (or call `set_peer_key` for runtime).

### 9.6 Reassign an SSIP device to a different carrier (root)

When an operator changes `ssip_devices.root` for some device id, the
device must start authenticating to the hub as the **new** carrier-bot
user (e.g. `dev-root-19` instead of `dev-root-5`). The mechanism is
PG-trigger-driven and automatic.

```sql
-- One-time DBA setup (per Law 1 the operator executes; mod_ssip_hub
-- never modifies tucall schema). Adds a trigger that fires when
-- ssip_devices.root changes and pings the hub via the existing
-- send_udp() helper that mod_ssip_hub's listener already understands.
CREATE OR REPLACE FUNCTION ssip_notify_root_change() RETURNS trigger AS $$
BEGIN
    IF NEW.root IS DISTINCT FROM OLD.root THEN
        -- Reuses the same UDP-from-PG-trigger plumbing as toupdate (U)
        -- and toreboot (R). Format matches the listener: <cmd>|<id>.
        PERFORM send_udp('K|' || NEW.id, '<hub_ip>', 1301);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ssip_devices_root_change_notify ON ssip_devices;
CREATE TRIGGER ssip_devices_root_change_notify
    AFTER UPDATE OF root ON ssip_devices
    FOR EACH ROW EXECUTE FUNCTION ssip_notify_root_change();
```

Once the trigger is in place, the runtime flow on every root change:

```
operator: UPDATE ssip_devices SET root = 19 WHERE id = 867;
   ↓ (PG trigger)
udp send_udp('K|867', hub, 1301)
   ↓ (mod_ssip_hub listener thread)
notify pipe → main loop → on_notify_pipe (cmd 'K')
   ↓
  - SELECT root FROM ssip_devices WHERE id = 867
  - ensure_carrier_bot_user(core, 19, &key)
  - core->send /ssip867/ssip/functions/set_hub_key key=<carrier-bot-19-key>
  - emit /events/ssip/hub/device_root_changed device_id=867 new_root=19
   ↓ (federation)
device handle_set_hub_key (auth: caller is local `hub` user)
  - sed -i  peer_keys = ssip-hub:<new-key>
  - sync; _exit(0)
   ↓ (systemd)
portal-default respawn → identity_proof exchange → hub resolves to dev-root-19
```

Verification: `journalctl -u portal-ssip_hub` shows `Re-key: pushed
new carrier-bot key to ssip867`; `journalctl -u portal-default` on
ssip867 shows `set_hub_key: peer_keys updated` then a fresh
`Identity exchange ok with peer 'ssip-hub' → local user 'dev-root-19'`
on reconnect.

If the device is offline at notify time, the push fails (logged on
hub). The device migration handler `/ssip/hub/functions/get_carrier_key`
will resolve it automatically on next boot, since the device's
`peer_keys` line will no longer authenticate against any current
carrier-bot user on the hub.

---

## 10. SSIP-specific layer (asymmetric trust)

The fleet is intentionally asymmetric:

- **Devices → hub**: minimal privilege. Every device in carrier
  `root_id = N` resolves on the hub to user `dev-root-<N>` with
  labels `ssip-device, ssip<N>`. Auto-provisioned by `mod_ssip_hub`
  on first register/restore. The carrier-bot api_key returns to the
  device on register-response line 3; `mod_ssip` writes it to
  `peer_keys = ssip-hub:<key>` and `_exit(0)`s for respawn.
- **Hub → devices**: maximal privilege. The hub's outbound key for
  `ssip<id>` is the device's own 128-hex `/etc/ssippwd`, which equals
  `ssip_devices.password` in PG. `mod_ssip_hub` seeds these via the
  runtime `set_peer_key` API at module load AND on every
  register/restore. The device has a local user `hub` whose api_key
  equals `/etc/ssippwd` (`mod_ssip` Phase 2b creates it at module
  load), with labels `root, admin, hub-admin` so the hub passes
  every gate that matters on the device.

Migration for already-deployed devices uses the
`/ssip/hub/functions/get_carrier_key` endpoint described in §5.4.
Operators don't need to re-register anything; a normal boot picks up
the missing key on the next cycle.

### 10.1 Implementation notes (gotchas the team hit)

- **Key length**: `auth_user_t.api_key` is `[AUTH_KEY_LEN + 1] = 65`
  bytes. `/etc/ssippwd` is 128 hex (SHA-512), so the local `hub` user
  on the device only stores the **first 64 chars**. Phase 2c on the
  hub therefore truncates the device password to 64 chars before
  pushing to `peer_keys`. Mismatch makes identity exchange silently
  resolve to anonymous on one side.
- **`root = 0` (dev / unassigned)**: `ensure_carrier_bot_user` accepts
  it (creates `dev-root-0` with labels `ssip-device, ssip0`) so dev
  boxes still get a low-priv carrier-bot for identity exchange.

### 10.2 Asymmetric shell (hub ↔ device)

Two layers enforce "hub→device shell works, device→hub shell denied":

1. **Identity layer** (covered by §5 and §6.2): a device→hub
   `/shell/functions/dialback_request` arrives as `dev-root-<N>`
   (labels `ssip-device, ssip<N>`), no `root` label → access_label
   gate denies → 403.
2. **Listener layer** (mod_shell). The dial-back TLS port (`:2223`)
   has a Strategy A "DIRECT" mode — the initiator opens the TCP and
   the target runs `/bin/su` locally. Strategy A bypasses Portal auth
   entirely (TLS-only path to a `/bin/su` prompt). On the **hub**, set
   `shell_disable_direct_target = true` in `mod_shell.conf` so the
   listener rejects every `DIRECT` line. Operator dial-back from the
   hub uses session_id mode and is unaffected (matched against an
   internally-tracked `pending_shell` created by an authenticated
   `/shell/functions/open_remote` on the hub side).

The two layers are independent — defeating one doesn't help an
attacker.

For full detail and the per-phase commit ledger see the auto-memory
entry `reference_federation_identity.md` and
`mod_ssip_hub/docs/create_update.md` (operator-side workflow for the
broader SSIP rollout pipeline).

---

## 11. Security debt — open items the audit surfaced and the team has not yet addressed

These exist independently of the federation-identity work and remain
on the table.

| Severity | Module | Issue | Where |
|---|---|---|---|
| HIGH | `mod_ssh` | Shell injection in `system("ssh-keygen … -f %s ", g_host_key)` | `mod_ssh.c:355-363` |
| HIGH | `mod_ldap` | Bind-DN/password stored plaintext in conf; no LDAPS; LDAP filter & DN injection in `snprintf(filter, …, g_user_filter, user)` | `mod_ldap.c:128-144, 180-183, 250, 252` |
| MED | `mod_firewall` | Rate limiter fails OPEN when tracker table fills (`FW_MAX_TRACKERS = 1024`) | `mod_firewall.c:124` |
| MED | `mod_web` | Accepts `?api_key=` in URL query string — visible in HTTP access logs | `mod_web.c:161-168` |
| MED | `mod_audit` | Log file is plaintext + clearable by `admin` — no HMAC chain, no tamper evidence | `mod_audit.c:82-91, 281-294` |
| MED | (default) | `tls_verify = false` ships as default for federation TLS | `src/main.c` template + `mod_node.c:31` |
| LOW | core | `mod_audit` does not record federation identity exchange success/failure | (gap) |

These are tracked here so the next person reading this doc can decide
which to take. Fixing them does not require any architectural change;
each is a localised module patch.

---

## 12. Threat model — what we defend, what we don't

**We defend against:**

- A compromised SSIP device leaking its own key compromises *only*
  that carrier's bot identity on the hub, which carries no admin
  labels (Phase 3 gate keeps it away from `/users`, `/groups`,
  `/core/modules`, `/core/config/set`).
- A casual web caller without an API key cannot read user records
  (anonymous → unlabeled but path is in handler scope) and cannot
  mutate anything.
- An operator scoped to one carrier label does not see other
  carriers' devices on the SSIP updates dashboard (Law 15).
- A federation peer cannot trivially impersonate another peer's
  identity — the identity exchange ties keys to user records on the
  receiving side.

**We do NOT defend against:**

- An attacker with access to the **shared `federation_key`** can
  complete the PORTAL02 handshake and join the mesh as an anonymous
  peer. Combined with a leaked api_key for any peer they could
  impersonate that peer's identity.
- An attacker who roots the hub host has access to the `users.conf`
  file, the storage backend, and every `mod_node.conf` containing
  `peer_keys`. Hardening the host is out of scope for Portal itself.
- An operator carrying `hub-admin` is fully privileged on the hub —
  there is no second-factor or quorum step on user creation, key
  rotation, or module load. Treat the `hub-admin` label as the
  highest-trust assignment.
- The audit log has no tamper-evidence (see §11). An admin who
  rooted the hub can clear it.

**Mitigations not yet implemented**: pieces in §11 + §13 below.

---

## 13. Small enhancements still worth doing

These are not blockers; they round out the model. Roughly ordered by
payoff per line-of-code.

1. **Audit events for identity exchange** — emit
   `/events/auth/identity_exchanged` and `/events/auth/identity_failed`
   from `mod_node`. ~30 lines. Closes §11 LOW item.
2. **Show resolved user in `/node/resources/peers`** — add a
   `Resolved as: <user>` column. ~10 lines. Diagnostic visibility.
3. **Per-peer key rotation handler** — one operator endpoint that
   ensures user, generates new key, pushes via `set_peer_key`, and
   (for SSIP) triggers per-device push via the existing `set_hub_key`
   plumbing.
4. **Flip `tls_verify = true` default** — once the operator has CA
   infrastructure. One-line change in the template.
5. The HIGH-severity items in §11 (mod_ssh injection, mod_ldap)
   whenever those modules are next touched.

---

## See also

- `docs/PHILOSOPHY.md` — Laws 8, 9, 15 in their canonical form.
- `docs/CORE_API.md` — module API for auth + label primitives.
- `docs/MODULE_GUIDE.md` — idiomatic patterns for module authors.
- `mod_ssip_hub/docs/create_update.md` — operator workflow for the
  SSIP staged-rollout pipeline.
- Auto-memory `reference_federation_identity.md` — implementation
  ledger for Phase 1–5 with file:line citations.
