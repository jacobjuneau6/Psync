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

If you want to try pwr on a single machine (localhost):

```bash
# 1. Start the server (user-mode, auto-detected)
pwr-server init          # generates config, TLS cert, PSK
pwr-server start         # daemonizes in the background

# 2. Configure the client (copy the PSK from step 1)
pwr init --server-host localhost --psk <hex-from-server-init>

# 3. Create your first project
cd ~/my-project
pwr create               # writes .project.toml
pwr archive .            # encrypts and uploads to server

# 4. Restore it later
pwr restore ~/my-project

# 5. Stop the server when done
pwr-server stop
```

---

## Server setup

### 1. Storage directory

The server stores project archives on disk. Create the directory and set
permissions for the user that will run `pwr-server`.

**System-wide (root):**

```bash
sudo mkdir -p /srv/pwr/projects
sudo chown pwr:pwr /srv/pwr/projects
sudo chmod 750 /srv/pwr/projects
```

**User-mode:** no manual setup needed — storage defaults to
`~/.local/share/pwr/projects` when system paths aren't writable.

### 2. Initialize

Generates a TLS certificate, private key, and pre-shared key (PSK).

```bash
# System-wide (as root):
sudo pwr-server init

# Unprivileged user (auto-detects XDG paths):
pwr-server init
```

Save the **PSK** hex string and **SHA-256 fingerprint** printed at the end —
you'll need them when configuring the client.

### 3. Start

```bash
pwr-server start              # daemonize into background
pwr-server start --foreground # run in foreground (debugging)
pwr-server start -f           # same as --foreground
```

### 4. Check status

```bash
pwr-server status
```

Shows the config file location, listen address, storage path, TLS status, and
whether the port is reachable.

### 5. Stop

```bash
pwr-server stop
```

Sends SIGTERM, waits 5 seconds for graceful shutdown, then escalates to
SIGKILL. Cleans up the PID file automatically.

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
| `--server-host` | `nas` | Server hostname or IP |
| `--server-port` | `9742` | Server TCP port |
| `--psk` | (generated) | Hex-encoded 256-bit pre-shared key |
| `--local-root` | `~/Projects` | Root directory for tracked projects |

The config is written to `~/.config/pwr/client.toml`.

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
| Client config | — | `~/.config/pwr/client.toml` |

To explicitly force user-mode, pass a config path under your home directory:

```bash
pwr-server --config ~/.config/pwr/server.toml init
pwr-server --config ~/.config/pwr/server.toml start
```

---

## Systemd service

A unit file is included at `pwr-server/pwr-server.service`. Copy and
enable it for a persistent system-wide install:

```bash
sudo cp pwr-server/pwr-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pwr-server
```

The unit assumes the binary is at `/usr/local/bin/pwr-server` and config at
`/etc/pwr/server.toml`. Edit `ExecStart` and `User` to match your setup.

Note: systemd manages the process lifecycle, so daemonization is not needed —
the service runs in the foreground under systemd's supervision.

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
| **rustls CryptoProvider error** | The binary handles this at startup. If compiling from source, ensure `ring` is enabled for `rustls` in `Cargo.toml`. |
| **"Not a directory"** | The `archive` and `create` commands need a directory path, not a file. |
| **"Project is already tracked"** | The directory already has a `.project.toml`. Use `pwr archive` to archive it. |
