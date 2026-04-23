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

# Portal — News

Operator-readable highlights of what landed and why. Most recent first.
For the canonical security reference see [`docs/SECURITY.md`](docs/SECURITY.md).
For implementation detail and per-commit history use `git log`.

---

## 2026-04-23 — CLI: recursive peer paths, cwd-aware shortcuts, path validation, TAB completion

Four changes landed between `d6e0de6` and `b7e0250` that together turn
the CLI into a real interactive tool across federation hops. The
underlying principle is the same — **[Philosophy Law 1 (Everything Is a
Path)](docs/PHILOSOPHY.md) + Law 7 (Nodes Are Peers)**: a remote path
must work exactly like a local path. Four corners that used to leak.

### Why this matters

Before this work:

- `cd /ssip-hub/ssip867` let you navigate into the remote peer's namespace,
  but `get sysinfo/resources/info` from that cwd returned `(unavailable)`
  because the hub did not strip its own name from the inbound path and
  re-route to `ssip867`.
- Shortcut commands (`sysinfo`, `uptime`, `health`, `metrics`) hardcoded
  the local resource path, so running `sysinfo` inside `/ssip-hub/ssip867`
  always returned the operator's own machine — a silent lie, not what
  the prompt implied.
- `cd gate` (typo; only `gateway` exists) was accepted. Subsequent
  commands returned `(empty)` / `(unavailable)` and the operator had no
  clue the cwd itself was fictitious.
- `cd ssip<TAB>` and `cd gate<TAB>` (inside a peer cwd) did nothing —
  the TAB completion engine only triggered on paths starting with `/`.

After this work, all four behave like a normal Unix shell against a
remote filesystem.

### What shipped

#### `mod_node` — transparent self-prefix strip (commit `d6e0de6`)

The hub's inbound dispatch now strips its own node name from a federation
message before routing. When the laptop sends
`/ssip-hub/ssip867/sysinfo/resources/info`, the hub sees the prefix
`/ssip-hub/` is its own `g_node_name`, rewrites the path to
`/ssip867/sysinfo/resources/info`, and the existing `/<peer>/*` handler
forwards the remainder to `ssip867`. One self-strip per inbound hop,
cascades naturally. Works without `advertise_peers` needing to leak the
peer roster — peers stay invisible to SSIP tenants by default, and the
laptop addresses them by full path anyway.

~22 lines in `mod_node.c:2890`. Zero change to the wire format, zero
config change, zero rebuild required on concentrators or SSIP devices.

#### `mod_cli` — cwd-aware shortcuts (commit `30f8f05`)

A small table inside `mod_cli.c`'s dispatcher now rewrites shortcut
commands as `get <cwd>/<path>` when the invoking client is inside a
non-root cwd:

```
sysinfo  → sysinfo/resources/all
uptime   → sysinfo/resources/os
health   → health/resources/checks
metrics  → metrics/resources/system
```

Result: `portal:/ssip-hub/ssip871> sysinfo` now queries ssip871's
sysinfo (hostname, IPs, kernel, CPUs), not the operator's. Matches the
prompt.

No ABI change — the rewrite is local to `mod_cli` and keyed on the
word list above. External modules don't need to know.

#### `core_handlers` — `cd` validates path existence (commit `82173e9`)

`/core/resolve` is no longer a pure string normalizer. It checks the
resolved path against the registry — either exact registered path or
prefix of any registered path — and returns `PORTAL_NOT_FOUND` if
neither matches. `mod_cli`'s `cmd_cd` prints `No such path` and
leaves cwd untouched:

```
portal:/> cd gate
No such path
portal:/> cd gateway
portal:/gateway>
```

Federated peers work transparently: `/ssip867/*` is a locally-registered
wildcard (direct peer), so `cd /ssip867/anything` passes the local check
and the deeper lookup falls to the remote on first `get`/`ls` — same
semantics as NFS-style `cd`.

#### `mod_cli` — TAB completion for `cd` / `ls` / `get` (commit `b7e0250`)

When the first word is `cd`, `ls`, or `get` and the operand doesn't
start with `/`, the tab engine now resolves the operand against cwd
(`cwd + "/" + word`) and runs the existing absolute-path completion
pipeline. Works identically for local and federated targets:

```
portal:/> cd ssip<TAB><TAB>
  ssip868/
  ssip/
  ssip841/
  ssip867/
portal:/> cd /ssip-hub/ssip867
portal:/ssip-hub/ssip867> cd gate<TAB>
portal:/ssip-hub/ssip867> cd gateway/
```

Single-TAB inserts the common prefix + trailing `/` when there is one
match; second TAB shows the candidate list.

### Operator action

None required — binary swap + service restart picks up all four.
Deploy is `make install` then restart Portal (systemd or gdb-inferior);
federation / identity / devices are untouched, no `/etc/ssippwd` wipe
needed. A partial deploy (some peers on old binary) is safe — each fix
is local to the node that runs it; mixed versions do not break federation.

### Notes for module authors

The cwd-aware shortcut table lives inside `mod_cli`. Modules that
register their own CLI shortcut via `portal_cli_register` and want
cwd-aware routing for it should either:

- Add their word+path to the `cwd_shortcuts[]` table in `mod_cli.c`
  (tiny patch), or
- Implement their own cwd resolution in their handler via the
  `cli_client_t` lookup pattern (see `mod_cli.c:579 cmd_cd` for the
  reference implementation).

An earlier attempt to extend `portal_cli_entry_t` with an optional
`path` field was reverted (commit `30f8f05`) because the cross-module
ABI change produced subtle memory corruption in designated-initializer
arrays when the two modules were rebuilt in slightly different orders.
The hardcoded table inside `mod_cli` is the simpler, lower-risk fix for
now; a future API extension can revisit that.

---

## 2026-04-19 — `mod_webhook` speaks HTTPS (make.com / Slack / Zapier / Discord)

`mod_webhook` previously parsed `https://` URLs but POSTed them in
plaintext on the parsed port. With `portal_main 2090ea7` it now
wraps the connection in TLS 1.2+ with SNI and full hostname
verification against the system trust store, so public webhook
receivers (make.com, Slack, Zapier, Discord, PagerDuty, …) work
out of the box.

### Why this matters

Operators wanted to plug Portal events into low-code automation
platforms — make.com / Zapier / n8n / Slack — without building a
side-car proxy or running an internal HTTPS terminator. With one
`register` call, any Portal event becomes a workflow trigger:

```bash
curl -X POST "http://core.tucall.com:8090/api/webhook/functions/register\
?name=ssip_offline_alerts\
&url=https://hook.eu1.make.com/<your-id>\
&event=/events/ssip/hub/device_offline\
&apikey=$KEY"
```

From then on, every `device_offline` event auto-POSTs JSON to make.com.

### What's in the box

- Per-hook `tls` flag set automatically by URL scheme (`https://` →
  TLS, default port 443; `http://` → plain, default port 80).
- Shared `SSL_CTX` created at module load, TLS 1.2 minimum, system
  trust store via `SSL_CTX_set_default_verify_paths()` (works on
  AlmaLinux, Debian, Ubuntu, RHEL — wherever ca-certificates is
  installed).
- SNI set on every connection (mandatory for Cloudflare / AWS-ALB /
  multi-tenant HTTPS terminators including make.com hooks).
- Full hostname verification by default. `tls_verify = false` opt-out
  in `mod_webhook.conf` for receivers behind self-signed certs —
  **never flip this for public receivers**.
- `register` rejects `https://` URLs with HTTP 400 if Portal was built
  with `HAS_SSL=no`, so misconfig fails loudly instead of silently
  dropping events.

### Operator action

- Existing HTTP webhooks: no change.
- New HTTPS webhooks: just register with `https://` URL — works.
- See [`mod_ssip_hub/docs/api_ssip_managed.md`](../mod_ssip_hub/docs/api_ssip_managed.md)
  §6.1 for the full make.com worked example, payload shape, and the
  list of useful SSIP events to bind webhooks to.

### Limitations to know

- **No exponential backoff**: 3 retries, then the event is dropped.
  For at-least-once delivery to a flaky receiver, queue with
  `mod_queue` and have a separate worker dispatch — `mod_webhook`
  is "best effort fire and forget".
- **No label gate today** on `/webhook/functions/register`. Any
  authenticated Portal user can register a hook. If you multi-tenant
  the hub, add a `hub-admin` label gate (one line in `mod_webhook.c`)
  before issuing API keys to external operators.
- **Hooks are in-memory**: they don't survive portal restart. Persist
  via a startup script that re-registers (or PR `mod_webhook` to
  load from `mod_webhook.conf`).

---

## 2026-04-19 — Federation identity hardened, asymmetric SSIP shell, mod_node disconnect-cleanup

The federation identity stack (Phase 1–5) shipped earlier this week is
now **fully live across the hub and the SSIP fleet**, with three
practical improvements that close real gaps the audit surfaced.

### Why this matters

Before this work, knowing the shared `federation_key` got a peer
treated as **local root** on every other Portal node — a single
compromised SSIP device could, in principle, walk every other peer in
the mesh. After Phase 5 the shared key only buys mesh membership;
identity is per-peer, resolved at handshake against each node's local
user registry, and downstream Law 8 / Law 15 deny anything labeled if
the resolved identity doesn't match.

The work this week stitched together two operational corners that
remained:

#### `federation_inbound_default_user` — opt-in escape hatch for devices

Phase 5 strict identity is the right default for multi-peer nodes
(the hub). For an SSIP device, however, identity_proof can fail
silently for boring reasons: a `root = 0` dev box has no carrier-bot
user, the SHA-512 `/etc/ssippwd` is 128 hex but `auth_user_t.api_key`
is 65 bytes (truncates), Phase 2c hub seeding may not have run yet
on first boot. Each of these makes the hub arrive at the device as
*anonymous* and the operator's `shell <device>` returns 403.

A new `mod_node.conf` knob covers it:

```
federation_inbound_default_user = hub
```

When set, anonymous inbound federation peers are stamped as the named
local user (defaults: NONE). Devices have one trusted peer (the hub),
gated by `federation_key` mesh membership, so treating that lone peer
as the local `hub` user (labels `root, admin, hub-admin`) is a safe
fallback. **Never set this on the hub** — it would inherit those
labels to anyone who knows `federation_key`.

#### `shell_disable_direct_target` — close the `:2223` bypass on the hub

`mod_shell`'s dial-back listener accepted a `DIRECT <rows> <cols>`
line that caused it to fork `/bin/su` immediately on the listener
side, with **no Portal authentication** — TLS reachability + a working
`/bin/su` PAM stack was enough. From an SSIP device the operator
chain `device → hub:2223` got a `core1 login:` prompt without going
through identity_proof or any label gate.

A new `mod_shell.conf` knob:

```
shell_disable_direct_target = true
```

makes the listener reject every `DIRECT` line. Operator
hub→device dial-back is unaffected because that path uses session_id
matching (a `pending_shell` entry that only an authenticated
`/shell/functions/open_remote` on this side can create). Set this on
the hub. Defaults to off on devices.

#### `mod_node` unregisters federation paths on disconnect

A peer reconnect would log:

```
[ERROR] FAILED to register path '/<peer>/*' for peer '<peer>' (rc=-1)
```

…and from then on, every dispatch to `/<peer>/<anything>` returned
404 because the stale path entry no longer routed to a live worker.
Surfaced most visibly as `shell <peer>` failing with status 404 even
though the peer was reconnected and otherwise healthy.

Disconnect handlers now mirror `path_register` with `path_unregister`
in both sites (ctrl_fd loss + last-worker loss), so reconnect re-runs
identity_proof and registers cleanly.

### Operator action

- Devices need `federation_inbound_default_user = hub` and a populated
  `peer_keys = ssip-hub:<carrier-bot-key>` (Phase 2a register-response
  line 3 writes it; the `/ssip/hub/functions/get_carrier_key`
  migration handler covers already-deployed devices on first boot).
- The hub needs `shell_disable_direct_target = true` in
  `mod_shell.conf`. No change needed in `mod_node.conf`; runtime
  Phase 2c seeding (now correctly truncated to 64 hex chars) populates
  the per-device peer_keys map at module load.

Full per-knob doc + threat model is in [`docs/SECURITY.md`](docs/SECURITY.md).
Companion operator runbooks live at
[`mod_ssip_hub/docs/security.md`](../mod_ssip_hub/docs/security.md)
(hub side) and [`mod_ssip/docs/security.md`](../mod_ssip/docs/security.md)
(device side).

### Where this leaves the system

- A compromised device key compromises only that device's carrier-bot
  identity on the hub (Phase 3 mutation gate keeps it away from
  `/users/`, `/groups/`, `/core/modules/`, `/core/config/set`).
- Hub→device shell goes through the federation identity layer **and**
  the listener-level DIRECT block — defense in depth.
- Device→hub shell is denied at both layers (identity gate + listener
  rejection of DIRECT).
- Operators on the hub are real Portal users with `ssip<N>` labels for
  carrier visibility (Law 15) plus `hub-admin` for mutation paths
  (Phase 3). The built-in Portal `root` user remains super-root,
  reachable only via the local CLI socket on the hub host.

---

## See also

- [`docs/SECURITY.md`](docs/SECURITY.md) — single source of truth for
  identity, ACLs, output filtering, federation identity, mutation
  gate, encryption, audit, operator runbooks, threat model.
- [`docs/PHILOSOPHY.md`](docs/PHILOSOPHY.md) — Laws 8 (path ACL),
  9 (module auth), 15 (group-scoped output filtering) in canonical
  form.
- `mod_ssip_hub/docs/create_update.md` — operator workflow for the
  staged-update pipeline that uses the same trust chain.
