# Psync — Lazy Project Archiver (`pwr`)

A Rust tool that archives projects from a laptop to a NAS and restores
them on demand. Uses a custom TLS-encrypted protocol instead of rsync,
with client-side age encryption so the server never sees plaintext data.

### Platform support

| Platform | Status |
|---|---|
| **Linux** (x86_64, aarch64) | ✅ Full support — server, client, TUI, systemd service |
| **macOS** | ❌ Not supported |
| **Windows** | ❌ Not supported |

## Architecture

```
pwr-core/       — Shared library: metadata, protocol, crypto, archive pipeline
pwr-server/     — NAS daemon: TLS listener, auth, project storage
pwr-cli/        — Client binary: CLI commands, TUI, shell integration
```

```
┌─────────────────┐         ┌──────────────────────┐
│     Laptop       │  TLS    │     NAS (Debian 12)   │
│                  │◄───────►│                      │
│  pwr (CLI+TUI)  │  :9742  │  pwr-server (daemon) │
└─────────────────┘         └──────────────────────┘
```

## Security

- **Transport**: TLS 1.3 with certificate pinning
- **Authentication**: PSK-based HMAC-SHA256 challenge-response
- **At-rest**: age (X25519) client-side encryption — server stores only ciphertext
- **Integrity**: SHA-256 hash verification on every transfer

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
### Currently only works with IPv4 so the hostname must resolve to and IPv4 address
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

## Project File Format

Each tracked project has a `.project.toml` in its directory:

```toml
version = 1
uuid = "550e8400-e29b-41d4-a716-446655440000"
name = "myproject"
local_path = "/home/jacob/Projects/myproject"
remote_path = "nas.local:9742:/srv/pwr/projects/myproject"
size_bytes = 14531252221
file_count = 342
last_sync = "2026-07-04T18:23:12Z"
state = "archived"
encryption_enabled = true
public_key = "age1qx0..."
```

After archiving, the directory contains only `.project.toml` — the
placeholder that triggers automatic restore when you `cd` into it.

## Commands

| Command | Description |
|---------|-------------|
| `pwr init` | Create client config (~/.config/pwr/config.toml) |
| `pwr archive <path>` | Encrypt and upload project, leave placeholder |
| `pwr restore <path>` | Download, decrypt, and extract project |
| `pwr ensure <path>` | Ensure project is local (for shell cd wrapper) |
| `pwr status` | Table of all tracked projects |
| `pwr list` | List projects with paths |
| `pwr log` | Transaction history |
| `pwr shell <sh>` | Generate shell integration (bash/zsh/fish) |
| `pwr tui` | Launch terminal UI (requires `--features tui`) |

## Configuration

### Client (~/.config/pwr/config.toml)

```toml
version = 2
server_host = "nas.local"
server_port = 9742
server_psk = "a1b2c3d4..."
use_tls = true
server_fingerprint = "sha256:..."
local_root = "/home/jacob/Projects"
connect_timeout_secs = 10
transfer_timeout_secs = 300
```

### Server (/etc/pwr/server.toml)

```toml
version = 1
listen_address = "[::]"
listen_port = 9742
storage_base_path = "/srv/pwr/projects"
max_project_size_gb = 500
tls_cert_path = "/etc/pwr/server.crt"
tls_key_path = "/etc/pwr/server.key"
auth_token = "a1b2c3d4..."
max_connections = 32
idle_timeout_secs = 300
```

## Building from Source

**Requirements**: Rust 1.96+, OpenSSL/LibreSSL development headers (for ring)

```bash
git clone https://github.com/jacob/psync
cd psync
cargo build --release           # CLI only
cargo build --release --features tui  # With TUI
cargo test                      # Run all tests
```

## Compatibility

| Platform | Status |
|---|---|
| **Linux** (x86_64, aarch64) | ✅ Full support — server, client, TUI, systemd service |
| **macOS** | ❌ Not supported — uses Linux-specific APIs (libc, systemd) |
| **Windows** | ❌ Not supported — uses Unix domain sockets and POSIX APIs |

The server and client both use:
- `libc` for daemonization, signal handling, and raw socket options
- systemd for service management (`--with-service`)
- Unix filesystem permissions (`chmod 0o600` for private keys)

These are deeply embedded and not abstracted behind platform gates.
A macOS client-only port (without the TUI or daemon features) may be
feasible; a Windows port is unlikely.

Both IPv4 and IPv6 are supported. The server binds dual-stack by default
(`[::]`) and falls back to `0.0.0.0` if IPv6 is unavailable. The client
tries all resolved addresses (v6 first, then v4).

## License

MIT
