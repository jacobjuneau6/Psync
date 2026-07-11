# pwr Installation & Usage Guide

pwr is a lazy project archiver — move projects you're not actively using from
your workstation to your NAS, and restore them on demand. All transfers are
encrypted, integrity-verified, and happen over TLS.

```
┌──────────────┐     TLS (port 9742)     ┌──────────────┐
│   pwr (CLI)  │ ◄──────────────────────► │  pwr-server   │
│  workstation │                          │     NAS       │
└──────────────┘                          └──────────────┘
```

- **`pwr`** — CLI client with an optional TUI. Archives projects as encrypted
  tarballs, uploads them to the server, and restores them on demand.
- **`pwr-server`** — daemon. Runs on the NAS, stores encrypted project blobs on
  disk, and serves them back to authorized clients.

---

## Table of contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Server setup](#server-setup)
- [Client setup](#client-setup)
- [CLI command reference](#cli-command-reference)
- [TUI](#tui-terminal-user-interface)
- [Project lifecycle](#project-lifecycle)
- [User-mode setup](#user-mode-setup)
- [Systemd service](#systemd-service)
- [Firewall](#firewall)
- [Troubleshooting](#troubleshooting)

---

## Installation

### From crates.io

```bash
cargo install pwr-cli --features tui
cargo install pwr-server
```

The `--features tui` flag enables the terminal user interface. Leave it off
for a headless CLI-only install.

### From source

```bash
git clone https://github.com/jacob/psync.git
cd psync

# Client (with TUI):
cargo install --path pwr-cli --features tui

# Server:
cargo install --path pwr-server
```

Both binaries end up in `~/.cargo/bin/`. Make sure that directory is on your
`$PATH` (added automatically by `rustup`).

---

## Quick start

This gets you from zero to a running server + client on a single machine in
under two minutes. For a two-machine setup (laptop → NAS), follow the same
steps but run the server commands on the NAS and the client commands on the
laptop.

### Prerequisites

- Rust toolchain (install via [rustup.rs](https://rustup.rs))
- Linux with systemd (for the service; you can also run the server manually)

### 1. Install

```bash
# Install both binaries from crates.io (~/.cargo/bin/)
cargo install pwr-cli --features tui
cargo install pwr-server
```

The `--features tui` flag enables the terminal UI. Leave it off for a
headless CLI-only client.

### 2. Initialize the server

This generates a TLS certificate, pre-shared key, config file, and
optionally installs the systemd service — all in one command.

```bash
# User-mode (no root): everything lives under ~/.config/pwr/
pwr-server init --with-service

# Save the PSK printed at the end — you'll need it for the client.
```

If you're running as root, it installs a system-wide service instead:

```bash
sudo pwr-server init --with-service
```

What `--with-service` does:
- Writes a systemd unit file to `~/.config/systemd/user/pwr-server.service`
  (or `/etc/systemd/system/pwr-server.service` if root)
- Uses the actual binary path — no manual `ExecStart=` editing
- Runs `systemctl daemon-reload` automatically
- Prints the `systemctl enable --now` command to copy-paste

### 3. Start the server

```bash
# User service (the init output told you this):
systemctl --user enable --now pwr-server

# Or, if you ran init as root:
sudo systemctl enable --now pwr-server

# Verify it's running:
systemctl --user status pwr-server     # user
sudo systemctl status pwr-server       # root
```

To make the user service survive logout (start at boot):

```bash
sudo loginctl enable-linger $USER
```

### 4. Configure the client

```bash
# Use the PSK hex string printed by pwr-server init
pwr init --server-host localhost --psk <hex-from-server-init>
```

If the server is on another machine, use its hostname or IP:

```bash
pwr init --server-host nas.local --psk <hex-key>
```

The config is written to `~/.config/pwr/config.toml`.

### 5. Archive your first project

```bash
# Create a project in the current directory
pwr create ~/my-project

# Archive it — this encrypts, uploads, and frees local disk space
pwr archive ~/my-project

# Restore it when you need it again
pwr restore ~/my-project
```

### 6. Check on things

```bash
pwr status           # see all tracked projects and their states
pwr tui              # browse with the terminal UI
pwr log              # view transfer history
pwr-server status    # server config and health check
```

### Manual start (no systemd)

If you prefer to run the server by hand:

```bash
pwr-server init               # generate config (skip --with-service)
pwr-server start              # daemonize into background
pwr-server start --foreground # stay in foreground (debugging)
pwr-server stop               # graceful shutdown
```



---

## Server setup

### 1. Initialize

Generates a TLS certificate, private key, pre-shared key (PSK), and
the server config file.

```bash
# Unprivileged user — XDG paths under ~/.config/pwr/ and ~/.local/share/pwr/
pwr-server init

# System-wide as root — uses /etc/pwr/ and /srv/pwr/projects/
sudo pwr-server init
```

Add `--with-service` to also install the systemd unit file in one step:

```bash
pwr-server init --with-service          # user service (systemctl --user)
sudo pwr-server init --with-service     # system service (root)
```

See the [Systemd service](#systemd-service) section for details.

Save the **PSK** hex string and **SHA-256 fingerprint** printed at the end —
you'll need them when configuring the client.

### 2. Storage directory

**User-mode:** no manual setup needed — storage defaults to
`~/.local/share/pwr/projects` when system paths aren't writable.

**System-wide (root):** create the directory and assign ownership:

```bash
sudo mkdir -p /srv/pwr/projects
sudo chown pwr:pwr /srv/pwr/projects
sudo chmod 750 /srv/pwr/projects
```

### 3. Start

```bash
pwr-server start              # daemonize into background
pwr-server start --foreground # run in foreground (debugging)
pwr-server start -f           # same as --foreground
```

If you used `--with-service`, start via systemd instead:

```bash
systemctl --user enable --now pwr-server     # user
sudo systemctl enable --now pwr-server       # root
```

### 4. Check status

```bash
pwr-server status
```

Shows the config file location, listen address, storage path, TLS status, and
whether the port is reachable.

### 5. Stop

```bash
pwr-server stop                               # manual daemon
systemctl --user stop pwr-server              # user service
sudo systemctl stop pwr-server                # system service
```

---

## Client setup

### 1. Configure

```bash
pwr init \
  --server-host nas.local \
  --psk <hex-from-server-init> \
  --local-root ~/Projects
```

Options:

| Flag | Default | Description |
|---|---|---|
| `--server-host` | `nas` | Server hostname or IP (DNS resolution is supported) |
| `--server-port` | `9742` | Server TCP port |
| `--psk` | (generated) | Hex-encoded 256-bit pre-shared key |
| `--local-root` | `~/Projects` | Root directory for tracked projects |

The config is written to `~/.config/pwr/config.toml`.

#### Config fields

```toml
version = 2
server_host = "nas.local"
server_port = 9742
server_psk = "a1b2c3d4..."
use_tls = true                  # set to false only for local dev without TLS
server_fingerprint = "sha256:..."  # optional cert pinning
local_root = "/home/jacob/Projects"
connect_timeout_secs = 10
transfer_timeout_secs = 300
```

- **`use_tls`** (default `true`): Must match the server. The server always uses
  TLS. Disable only for development or if you're proxying TLS externally.
- **`server_fingerprint`** (optional): Pin the server's TLS certificate to
  prevent MITM attacks. The fingerprint is printed by `pwr-server init`. Leave
  unset to accept any self-signed certificate (PSK auth still applies).

### 2. Test connectivity

```bash
pwr status
```

If the server is reachable and the PSK matches, you'll see a list of all
tracked projects and their current state.

---

## CLI command reference

### `pwr init` — configure the client

```bash
pwr init --server-host nas.local --psk abc123...
```

### `pwr create` — start tracking a project

Creates a `.project.toml` inside a directory, registering it as a tracked
project.

```bash
pwr create                  # use current directory
pwr create ~/Projects/app   # specify a path
pwr create --name "My App"  # override the project name
```

The project starts in **local** state. A UUID is generated and printed —
this is the stable identifier that survives renames and moves.

### `pwr archive` — archive a project to the server

Encrypts the project directory, uploads it to the server, removes local
files (keeping only the `.project.toml` placeholder), and frees disk space.

```bash
pwr archive .               # archive current directory
pwr archive ~/Projects/app  # archive a specific project
pwr archive . --dry-run     # preview without uploading
pwr archive . -n            # same as --dry-run
```

### `pwr restore` — restore a project from the server

Downloads the encrypted archive, decrypts and extracts it, restoring the
project to a local state.

```bash
pwr restore ~/Projects/app  # restore to original location
pwr restore .               # restore current directory (must be placeholder)
pwr restore . --dry-run     # preview without downloading
```

### `pwr ensure` — guarantee a project is local

For shell wrapper integration. If the project is archived, restores it
automatically. If it's already local, does nothing.

```bash
pwr ensure ~/Projects/app
pwr ensure ~/Projects/app --quiet  # suppress output
```

### `pwr status` — show project states

```bash
pwr status           # check direct children of local-root
pwr status --recursive  # search subdirectories too
```

Output:

```
STATUS     NAME                 SIZE         LAST SYNC
-----------------------------------------------------------
local      my-app              45.2 MB      2026-07-10
archived   old-experiment      1.2 GB       2026-05-22
local      website             312.8 MB     2026-07-11

2 local, 1 archived (3 total)
```

### `pwr list` — alias for `pwr status`

Same output format. Accepts `--recursive` / `-r`.

### `pwr log` — view transaction history

```bash
pwr log                  # all transactions
pwr log my-app           # filter by project name
pwr log --errors         # show error details
pwr log my-app -e        # combine filters
```

### `pwr shell` — shell integration

```bash
pwr shell bash           # print bash completion script
pwr shell zsh            # print zsh completion script
pwr shell fish           # print fish completion script
pwr shell bash --init    # print instructions for .bashrc
```

### `pwr tui` — launch the terminal UI

```bash
pwr tui
```

---

## TUI (terminal user interface)

Launch with `pwr tui` (requires `--features tui` at install time).

```
┌─ Projects (1) ── Create (2) ── Log (3) ───────────────────┐
│                                                             │
│  STATUS     NAME                 SIZE         LAST SYNC     │
│  ───────────────────────────────────────────────────────    │
│  local      my-app              45.2 MB      2026-07-10    │
│  archived   old-experiment      1.2 GB       2026-05-22    │
│                                                             │
│  q quit | Tab switch | 1-3 tabs | ? help                   │
└─────────────────────────────────────────────────────────────┘
```

**Tabs:**

| Key | Tab | Description |
|---|---|---|
| `1` | Projects | Browse tracked projects, see their state and size |
| `2` | Create | Interactive form to create a new `.project.toml` |
| `3` | Log | Scrollable transaction history |

**Keyboard shortcuts (global):**

| Key | Action |
|---|---|
| `q` / `Esc` | Quit |
| `Tab` | Next tab |
| `1`–`3` | Jump to tab |

**Create tab shortcuts:**

| Key | Action |
|---|---|
| `Tab` / `Shift+Tab` | Switch between name / path fields |
| `Ctrl+S` | Save `.project.toml` |
| `Esc` | Cancel (switch to another tab) |

---

## Project lifecycle

A project goes through three phases:

### 1. Create (once)

```bash
pwr create ~/Projects/my-app
```

This writes a `.project.toml` with a stable UUID, the project name, local and
remote paths, and marks the state as `local`.

### 2. Archive (free up space)

```bash
pwr archive ~/Projects/my-app
```

What happens:
1. Directory size and file count are measured
2. An age-encrypted tarball is created
3. The archive is uploaded to the server over TLS
4. Local files are removed, leaving only `.project.toml`
5. The project state becomes `archived`

### 3. Restore (bring back)

```bash
pwr restore ~/Projects/my-app
```

What happens:
1. The encrypted archive is downloaded from the server
2. It's decrypted with the local age identity
3. SHA-256 integrity is verified
4. Files are extracted to the original directory
5. The project state becomes `local`

### States at a glance

```
   create        archive        restore
┌─────────┐    ┌──────────┐    ┌─────────┐
│  LOCAL  │───►│ ARCHIVED │───►│  LOCAL  │
│ (files  │    │ (.toml   │    │ (files  │
│  on     │    │  only)   │    │  back)  │
│  disk)  │    └──────────┘    └─────────┘
└─────────┘
```

---

## User-mode setup

When running as an unprivileged user, everything lives under your home
directory using XDG standard paths. The server auto-detects writability
and picks the right location automatically.

| What | System path | User (XDG) fallback |
|---|---|---|
| Server config | `/etc/pwr/server.toml` | `~/.config/pwr/server.toml` |
| TLS cert | `/etc/pwr/server.crt` | `~/.config/pwr/server.crt` |
| TLS key | `/etc/pwr/server.key` | `~/.config/pwr/server.key` |
| Storage | `/srv/pwr/projects` | `~/.local/share/pwr/projects` |
| PID file | `/run/pwr/pwr-server.pid` | `$XDG_RUNTIME_DIR/pwr/pwr-server.pid` |
| Client config | — | `~/.config/pwr/config.toml` |

To explicitly force user-mode, pass a config path under your home directory:

```bash
pwr-server --config ~/.config/pwr/server.toml init
pwr-server --config ~/.config/pwr/server.toml start
```

See the [Quick start](#quick-start) section for a complete walkthrough.

---

## Systemd service

### Automatic install (recommended)

The easiest way is to use `--with-service` during init. It detects whether
you're root or not, writes the correct unit file using the actual binary path,
and reloads systemd — all in one step:

```bash
# User service (no root needed)
pwr-server init --with-service

# System service (root)
sudo pwr-server init --with-service
```

Then enable and start:

```bash
systemctl --user enable --now pwr-server     # user
sudo systemctl enable --now pwr-server       # root
```

The service templates are embedded in the binary — no external `.service`
files needed. `--with-service` substitutes the actual `pwr-server` binary
path and config path, so you never need to edit `ExecStart=` by hand.

To make a user service start at boot (even when you're not logged in):

```bash
sudo loginctl enable-linger $USER
```

### Manual install

If you prefer to manage the unit file yourself, static copies are included
in the repo at `pwr-server/`:

- **`pwr-server.service`** — system-wide install (dedicated `pwr` user, root
  required).
- **`pwr-server.user.service`** — per-user install (your own account, no root).

```bash
# User service (manual)
mkdir -p ~/.config/systemd/user
cp pwr-server/pwr-server.user.service ~/.config/systemd/user/pwr-server.service
# Edit ExecStart= to point at your binary if not at ~/.cargo/bin/pwr-server
systemctl --user daemon-reload
systemctl --user enable --now pwr-server

# System service (manual, as root)
sudo cp target/release/pwr-server /usr/local/bin/
sudo cp pwr-server/pwr-server.service /etc/systemd/system/
# Edit User=, ExecStart=, ReadWritePaths= to match your setup
sudo systemctl daemon-reload
sudo systemctl enable --now pwr-server
```

### Managing the service

```bash
# User service
systemctl --user status pwr-server
systemctl --user stop pwr-server
systemctl --user restart pwr-server
journalctl --user -u pwr-server --since "10 min ago"
journalctl --user -u pwr-server -f            # follow live

# System service (root)
sudo systemctl status pwr-server
sudo systemctl stop pwr-server
sudo systemctl restart pwr-server
journalctl -u pwr-server --since "10 min ago"
journalctl -u pwr-server -f                   # follow live
```

---

## Firewall

The server listens on port **9742/tcp** by default:

```bash
# ufw
sudo ufw allow 9742/tcp

# firewalld
sudo firewall-cmd --add-port=9742/tcp --permanent
sudo firewall-cmd --reload

# iptables (manual)
sudo iptables -A INPUT -p tcp --dport 9742 -j ACCEPT
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| **"Config not found" on start** | Search order: `--config` flag → `./server.toml` → `~/.config/pwr/server.toml` → `/etc/pwr/server.toml`. Run `pwr-server init` first. |
| **"auth_token must not be empty"** | Run `pwr-server init` — it generates the PSK and writes a valid config. |
| **TLS certificate missing** | Run `pwr-server init` to regenerate the self-signed cert, then update the client PSK. |
| **Connection refused** | Check `pwr-server status`. Verify firewall allows port 9742. |
| **Permission denied on storage** | `chown` the storage dir to the user running the server, or switch to user-mode. |
| **`Invalid address: invalid socket address syntax`** | The `server_host` in `~/.config/pwr/config.toml` must be a hostname or IP, not a URL. Use `nas.local` or `192.168.1.100`, not `http://nas.local`. Hostnames are resolved via DNS. |
| **`Could not automatically determine CryptoProvider`** | The client needs rustls to be initialized. If building from source, make sure the `ring` feature is enabled for `rustls`. The prebuilt binary handles this automatically. |
| **`received corrupt message of type InvalidContentType`** | TLS mismatch — the client is connecting without TLS but the server requires it. Set `use_tls = true` in your client config, or check that both sides agree on TLS settings. |
| **"Not a directory"** | The `archive` and `create` commands need a directory path, not a file. |
| **"Project is already tracked"** | The directory already has a `.project.toml`. Use `pwr archive` to archive it. |
| **Server doesn't survive logout** | Run `sudo loginctl enable-linger $USER` so the systemd user manager keeps running after logout. |
