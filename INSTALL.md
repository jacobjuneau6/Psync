# pwr Installation Guide

pwr is a lazy project archiver with a client (`pwr`) and a NAS-side daemon
(`pwr-server`). Both communicate over TLS with pre-shared key authentication.

## Overview

```
┌──────────────┐     TLS (port 9742)     ┌──────────────┐
│   pwr (CLI)  │ ◄──────────────────────► │  pwr-server   │
│  workstation │                          │     NAS       │
└──────────────┘                          └──────────────┘
```

- **`pwr`** — CLI client. Archives projects as encrypted tarballs, sends them to
  the server, and restores them on demand.
- **`pwr-server`** — daemon. Runs on the NAS, stores encrypted project blobs on
  disk under a configurable storage path.

---

## Installation

### From crates.io (recommended)

```bash
cargo install pwr
cargo install pwr-server
```

### From source

```bash
git clone https://github.com/jacob/psync.git
cd psync

cargo install --path pwr-cli
cargo install --path pwr-server
```

Both binaries end up in `~/.cargo/bin/`. Make sure that directory is on your
`$PATH` (typically added by `rustup`).

---

## Server setup

### 1. Create the storage directory

The server stores project archives on disk. Choose a location and set
permissions so the user running `pwr-server` can read and write there.

**System-wide install (root):**

```bash
sudo mkdir -p /srv/pwr/projects
sudo chown pwr:pwr /srv/pwr/projects
sudo chmod 750 /srv/pwr/projects
```

You can also run the server as an unprivileged user — see
[User-mode setup](#user-mode-setup) below.

### 2. Initialize the server

This generates a TLS certificate, private key, and a pre-shared key (PSK).
It writes the server configuration to `/etc/pwr/server.toml`.

**As root (system-wide):**

```bash
sudo pwr-server init
```

**As an unprivileged user (user-mode):**

The server detects when system paths aren't writable and falls back to XDG
directories automatically:

```bash
pwr-server init
# → config written to ~/.config/pwr/server.toml
# → cert/key written to ~/.config/pwr/
# → storage defaults to ~/.local/share/pwr/projects
```

Take note of the **PSK** and **fingerprint** printed at the end — you'll need
them to configure the client.

### 3. Start the server

**Background (daemonized):**

```bash
pwr-server start
```

**Foreground (debugging):**

```bash
pwr-server start --foreground
# or: pwr-server start -f
```

### 4. Verify it's running

```bash
pwr-server status
```

Output includes the listen address, storage path, TLS status, and whether the
port is reachable.

### 5. Stop the server

```bash
pwr-server stop
```

Sends SIGTERM, waits 5 seconds for graceful shutdown, then escalates to
SIGKILL if needed. Cleans up the PID file automatically.

---

## Systemd (system-wide install)

A systemd unit file is included at `pwr-server/pwr-server.service`.
Copy it to `/etc/systemd/system/` and edit as needed:

```bash
sudo cp pwr-server/pwr-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pwr-server
```

The unit assumes the server binary is at `/usr/local/bin/pwr-server` and the
config at `/etc/pwr/server.toml`. Adjust `ExecStart` and `User` to match your
setup.

---

## Client setup

### 1. Install the client

```bash
cargo install pwr
```

### 2. Configure the client

You need the server's hostname (or IP), the PSK from server initialization,
and optionally the TLS certificate fingerprint for MITM protection.

```bash
pwr init --server-host my-nas.local --psk <hex-psk>
```

To pin the server's certificate (recommended):

```bash
pwr init --server-host my-nas.local --psk <hex-psk> --fingerprint <sha256-hex>
```

The fingerprint was printed during `pwr-server init`. You can also retrieve
it from the server:

```bash
ssh my-nas.local sha256sum /etc/pwr/server.crt
```

This writes `~/.config/pwr/client.toml`.

### 3. Test connectivity

```bash
pwr status
```

If the server is reachable and the PSK matches, you'll see the server's
version and storage stats.

---

## Usage

### Archive a project

```bash
cd ~/projects/my-app
pwr archive
```

This creates an encrypted tarball and uploads it to the server. A UUID is
assigned and printed — save it to restore later.

### List archived projects

```bash
pwr list
```

### Restore a project

```bash
pwr restore <uuid> --output /tmp/my-app-restored
```

### Shell integration

The client ships with shell tab-completion scripts in `pwr-cli/shell/`.
Source the one for your shell:

```bash
# bash
source <(pwr completions bash)

# zsh
source <(pwr completions zsh)

# fish
pwr completions fish | source
```

---

## User-mode setup

When running as an unprivileged user (no root, no `sudo`), everything
lives under your home directory using XDG standard paths:

| What | System path | User (XDG) path |
|---|---|---|
| Config | `/etc/pwr/server.toml` | `~/.config/pwr/server.toml` |
| TLS cert | `/etc/pwr/server.crt` | `~/.config/pwr/server.crt` |
| TLS key | `/etc/pwr/server.key` | `~/.config/pwr/server.key` |
| Storage | `/srv/pwr/projects` | `~/.local/share/pwr/projects` |
| PID file | `/run/pwr/pwr-server.pid` | `$XDG_RUNTIME_DIR/pwr/pwr-server.pid` |

The server auto-detects writability and chooses the right set of paths. To
force user-mode explicitly, pass a config path under your home directory:

```bash
pwr-server --config ~/.config/pwr/server.toml init
pwr-server --config ~/.config/pwr/server.toml start
pwr-server --config ~/.config/pwr/server.toml status
```

---

## Firewall

The server listens on port **9742/tcp** by default. Open it if the client is
on a different machine:

```bash
# ufw
sudo ufw allow 9742/tcp

# firewalld
sudo firewall-cmd --add-port=9742/tcp --permanent
sudo firewall-cmd --reload
```

---

## Troubleshooting

**"Config not found" on start:**
The `find_config` search order is: `--config` flag → `./server.toml` →
`~/.config/pwr/server.toml` → `/etc/pwr/server.toml`. Make sure the config
exists at one of those locations.

**"auth_token must not be empty":**
Run `pwr-server init` first — it generates the PSK and writes a valid config.

**TLS certificate missing:**
`pwr-server init` generates a self-signed cert. If you lost it, re-run
`init` and update the client PSK.

**Connection refused:**
Check that the server is running (`pwr-server status`) and the port is
reachable through any firewalls.

**Permission denied on storage path:**
The user running `pwr-server` must have read+write access to the storage
directory. Either `chown` it to that user or switch to user-mode setup.

**rustls CryptoProvider error:**
If you're compiling from source and hit this, make sure the `ring` feature
is enabled for `rustls` in `Cargo.toml`. The binary crate already handles
this at startup.
