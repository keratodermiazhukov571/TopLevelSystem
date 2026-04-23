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

# mod_sip — SIP/RTP Bridge Module — Design Document

## Overview

`mod_sip` bridges SIP calls between a local GABpbx (Asterisk/FreeSWITCH) instance
and remote Portal peers over federation. Both audio channels stream in real time.
The module is symmetric: every Portal node running `mod_sip` can originate and
receive federated calls.

---

## Architecture

### Two-Socket Per Peer Pair

```
Local Node                                 Remote Node
─────────────────────────────────────────────────────────────
GABpbx ←── SIP/RTP ──→ mod_sip            mod_sip ←── SIP/RTP ──→ GABpbx

             │  TCP (mod_node federation)  │
             │  ── SIP signaling msgs ──→  │
             │  ←── SIP signaling msgs ──  │

             │  UDP (mod_sip media socket) │
             │  ══ RTP audio (all calls) ══│
```

**TCP connection** (existing `mod_node` federation workers):
- Carries SIP signaling: INVITE, 200 OK, BYE, REFER, ACK
- Portal messages: path `/sip/...`, methods CALL/EVENT
- Reliable, ordered — correct for signaling

**UDP socket** (one per peer pair, opened by mod_sip):
- Carries all RTP media for all active calls multiplexed
- No head-of-line blocking — packet loss affects only that packet
- Capacity: bandwidth-limited only (thousands of calls)

### UDP Media Packet Framing

```
 0               1               2               3
 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
├───────────────┴───────────────┼───────────────┴───────────────┤
│           length (2B)         │        call_id_hash (4B)       │
├───────────────────────────────┴───────────────────────────────┤
│  stream_id (1B)  │              RTP payload ...                │
└──────────────────┴────────────────────────────────────────────┘
```

- `length` — total packet length including this header
- `call_id_hash` — FNV-1a hash of call UUID, maps to active call state
- `stream_id` — `0` = A-leg (caller → callee), `1` = B-leg (callee → caller)
- RTP payload — standard G.711/G.722/Opus RTP packet as-is

One `recvfrom()` call receives both directions. Demux is done in the read loop.

---

## Capacity

G.711, 20ms ptime:
- 50 pps × (12 RTP hdr + 160 payload) = 172 bytes/packet
- Per call, full duplex: ~136 kbit/s + UDP framing overhead
- **UDP**: no head-of-line blocking → thousands of calls per peer pair (bandwidth limited)
- **TCP signaling**: SIP messages are <2 KB → hundreds of concurrent setup/teardowns

---

## Portal Paths

| Path                 | Method | Access | Description                          |
|----------------------|--------|--------|--------------------------------------|
| `/sip/calls`         | GET    | READ   | List active calls                    |
| `/sip/calls/{id}`    | GET    | READ   | Call detail (state, legs, peer, dur) |
| `/sip/dial`          | CALL   | WRITE  | Originate outbound call to peer      |
| `/sip/hangup`        | CALL   | WRITE  | Hang up call by id                   |
| `/sip/transfer`      | CALL   | WRITE  | Blind or attended transfer           |
| `/sip/peers`         | GET    | READ   | List configured SIP peers            |
| `/sip/peers/{name}`  | GET    | READ   | Peer detail (host, port, state)      |
| `/sip/status`        | GET    | READ   | Module health (calls, bytes/s, state)|

---

## Events Emitted (Law 10)

| Event                    | When                              |
|--------------------------|-----------------------------------|
| `sip.call.ringing`       | INVITE sent or received           |
| `sip.call.answered`      | 200 OK exchanged                  |
| `sip.call.hungup`        | BYE sent or received              |
| `sip.call.failed`        | 4xx/5xx received                  |
| `sip.transfer.blind`     | REFER sent (blind transfer)       |
| `sip.transfer.attended`  | REFER+Replaces sent (attended)    |
| `sip.media.start`        | First RTP packet received         |
| `sip.media.stop`         | RTP silence >3s (keepalive miss)  |
| `sip.peer.registered`    | Peer connection established       |
| `sip.peer.lost`          | Peer connection dropped           |

---

## Resource Locks (Law 14)

- Each active call acquires exclusive lock on `/sip/calls/{id}` at answer time
- Lock auto-releases on BYE or after 60s without RTP keepalive
- Peer config paths `/sip/peers/{name}` locked while at least one call is active
- Prevents config changes from mid-call disruption

---

## Call Transfer Flows

### Blind Transfer (RFC 3515)
```
A ──REFER Refer-To:B──→ mod_sip ──/sip/transfer──→ federation ──→ remote mod_sip
                                                                  └──INVITE──→ B
```

### Attended Transfer (RFC 3891 — Replaces)
```
1. A calls X (consultation call established)
2. A sends REFER Refer-To:B?Replaces=X-dialog-id
3. mod_sip routes via federation to remote peer
4. Remote mod_sip sends INVITE to B with Replaces header
5. B takes over X's dialog, A is disconnected
```

### Federated Transfer
- REFER is always routed through Portal path `/sip/transfer`
- Federation (mod_node TCP) carries the signaling message to remote node
- Remote `mod_sip` generates the new INVITE to its local GABpbx
- No direct SIP signaling crosses the Portal federation boundary

---

## Thread Model (Law 13 — Never Block)

- **SIP parser thread**: reads from GABpbx SIP socket, parses SIP messages,
  posts to libev via `core->send()` — never blocks event loop
- **RTP read thread**: `recvfrom()` loop on UDP media socket, demuxes by
  call_id_hash, forwards to GABpbx RTP port for active call
- **RTP write thread**: reads from GABpbx RTP (via fd_add/epoll), wraps in
  media frame header, `sendto()` on UDP media socket
- **Event loop**: receives portal messages, drives state machine, emits events

Thread pool size: configurable via `mod_sip.conf` → `rtp_threads = 4`

---

## Config File Template (mod_sip.conf)

```ini
# mod_sip — SIP/RTP Bridge Module
# Portal module to bridge GABpbx SIP calls to remote Portal peers

[mod_sip]

# Local GABpbx SIP endpoint
gabpbx_host     = 127.0.0.1
gabpbx_port     = 5060
gabpbx_user     = portal
gabpbx_password =

# Local UDP port for inter-Portal RTP media
media_port      = 7070

# Thread pool for RTP I/O (Law 13)
rtp_threads     = 4

# Codec preference (G.711u, G.711a, G.722, Opus)
codec           = G.711u
ptime           = 20

# RTP keepalive timeout (seconds) — triggers resource lock release (Law 14)
rtp_timeout     = 60

# SIP registration refresh interval (seconds)
register_interval = 300
```

---

## Law Compliance Summary

| Law | Requirement                          | How mod_sip satisfies it                        |
|-----|--------------------------------------|-------------------------------------------------|
| 7   | Core READ-ONLY                       | Pure .so module, no core file changes           |
| 8   | Resources declare R/W/RW             | All 8 paths have explicit access mode           |
| 9   | Module authenticates on load         | Loads with configured labels, default = root    |
| 10  | Every change emits event             | 10 events covering full call lifecycle          |
| 12  | Universal resource names             | All paths use standard /sip/... syntax          |
| 13  | Never block event loop               | SIP parser + RTP I/O in dedicated threads       |
| 14  | Exclusive resource locking           | Per-call locks, 60s auto-release on RTP silence |

---

## Future: mod_overlay (Reading B — Deferred)

A future `mod_overlay` module could create a TUN/TAP virtual interface using
`/dev/net/tun`, building a full L3 overlay network between Portal nodes. This
would allow standard SIP and RTP to flow through the overlay with no
per-call multiplexing. Requirements:
- `CAP_NET_ADMIN` capability
- Kernel TUN support
- More complex routing (IP forwarding between peers)

Deferred: `mod_sip` (Reading A) is simpler, Portal-idiomatic, and sufficient
for the GABpbx federation use case. Reading B may be appropriate for a
general-purpose VPN/overlay module separately.

---

## SSIP Study (Pending)

A real SSIP implementation runs at `10.200.1.71` (user: monitor, password: kliouz9).
Scripts at `/usr/bin/ssip_*` and `/etc/crontab` document its implementation.
This system should be studied to:
- Identify call flow patterns not covered above
- Find edge cases in SIP transfer handling
- Understand scheduling/retry logic in production SSIP

Access requires a machine on the 10.200.x.x network (host unreachable from build env).
