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

# mod_shell — Remote Interactive Shell via Federation

SSH-quality interactive terminal access to any federated Portal peer. Uses real PTY (`forkpty()`) — htop, vi, top, less, sudo all work with full terminal rendering.

## Quick Start

```
portal:/> shell ssip888
Connected to ssip888 (Ctrl-] to disconnect)
root@ssipdev:~# htop
(full interactive display, fills entire terminal)
root@ssipdev:~# ^]
Disconnected
portal:/>
```

## How It Works

mod_shell provides session-based PTY access for HTTP/API clients. The CLI `shell` command uses **dedicated relay threads** via mod_node instead (see below).

- **Real PTY**: `forkpty()` allocates a kernel pseudo-terminal — full ncurses, job control, signals
- **Raw byte proxy**: every keystroke goes directly to the PTY (no local line editing)
- **Dedicated relay threads**: each shell session gets its own thread (no event loop blocking)
- **Terminal size propagation**: `portal -r` and `portalctl` send `__winsize <rows> <cols>` at connect time
- **ANSI passthrough**: escape sequences pass through untouched — full terminal rendering
- **Clean exit**: terminal reset on disconnect (`\033[?25h\033[0m\033[?1049l\033c`)
- **Auto-disconnect**: PTY child death detected, triggers clean exit
- **Ctrl-]** (0x1D): disconnect and return to Portal CLI (like telnet)
- **Bidirectional**: device → hub and hub → device both work via federation

## CLI Shell Architecture

The `shell` command in mod_cli uses a different path than the HTTP API:

- **Local** (`shell`): mod_cli forks PTY directly + spawns relay thread (PTY fd ↔ client fd)
- **Remote** (`shell <peer>`): mod_node's `/node/functions/shell` acquires a federation worker, sends `/tunnel/shell` to the remote peer (which forks a PTY), then relays in a background thread (worker fd ↔ socketpair ↔ client fd)

This architecture means the event loop is **never blocked** during shell I/O. All bytes flow through dedicated threads, not timers or message polling.

## Terminal Size

Terminal dimensions are propagated through the full chain:

1. `portal -r` / `portalctl` detects terminal size via `ioctl(TIOCGWINSZ)`
2. Sends `__winsize <rows> <cols>` hidden command to mod_cli
3. mod_cli stores dimensions in client state (`term_rows`, `term_cols`)
4. On `shell <peer>`, dimensions are sent as `rows`/`cols` headers
5. PTY size set via `ioctl(master_fd, TIOCSWINSZ, &ws)` at creation
6. On terminal resize, `ioctl(TIOCSWINSZ)` updates the local PTY

## Paths

| Path | Access | Description |
|------|--------|-------------|
| `/shell/functions/exec` | RW (admin) | Stateless: execute command via popen. Header: cmd |
| `/shell/functions/open` | RW (admin) | Open PTY session. Returns session_id. Headers: rows, cols |
| `/shell/functions/write` | RW (admin) | Send input to PTY. Header: session. Body: raw bytes |
| `/shell/functions/read` | RW (admin) | Read output from PTY. Header: session |
| `/shell/functions/close` | RW (admin) | Close PTY session. Header: session |
| `/shell/functions/resize` | RW (admin) | Resize terminal. Headers: session, rows, cols |

## Configuration

```ini
# mod_shell.conf
enabled = true
[mod_shell]
timeout = 10           # Max seconds per stateless command
shell = /bin/bash      # Shell binary for PTY sessions
allow_exec = true      # Safety switch (false disables all execution)
max_output = 65536     # Max bytes per read operation
session_ttl = 3600     # Auto-close inactive sessions (seconds)
```

## Security

All paths require label `admin`. Every execution emits `/events/shell/exec` for audit trail. The `allow_exec = false` config disables all execution as a safety switch.

## HTTP API

```bash
# Stateless exec
curl -u root:<pass> -X PUT "http://host:8080/api/shell/functions/exec?cmd=hostname"

# PTY session
SID=$(curl -s -u root:<pass> -X PUT "http://host:8080/api/shell/functions/open?rows=24&cols=80")
curl -s -u root:<pass> -X PUT "http://host:8080/api/shell/functions/write?session=$SID" -d "ls -la"
curl -s -u root:<pass> -X PUT "http://host:8080/api/shell/functions/read?session=$SID"
curl -s -u root:<pass> -X PUT "http://host:8080/api/shell/functions/resize?session=$SID&rows=50&cols=120"
curl -s -u root:<pass> -X PUT "http://host:8080/api/shell/functions/close?session=$SID"

# Remote via federation
curl -u root:<pass> -X PUT "http://hub:8090/api/ssip888/shell/functions/exec?cmd=uptime"
```

## CLI Integration

The `shell` command in mod_cli provides the interactive experience using dedicated relay threads:

```
portal:/> shell              # Local shell (forkpty + relay thread)
portal:/> shell ssip888      # Remote shell via /node/functions/shell
portal:/> shell ssip-hub     # Shell into the hub
```

Features:
- Dedicated relay thread per session (never blocks event loop)
- Raw byte proxy mode (bypasses line editor)
- Ctrl-] to disconnect cleanly
- Terminal reset on exit (cursor, colors, alternate screen buffer)
- Works through `portal -n <name> -r` and `portalctl`
