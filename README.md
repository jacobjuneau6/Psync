# Psync — Lazy Project Archiver (`pwr`)

A Rust tool that archives projects from a laptop to a NAS and restores
them on demand. Uses a custom TLS-encrypted protocol instead of rsync,
with client-side age encryption so the server never sees plaintext data.

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

## Quick Start

### Server (NAS — Debian 12)

```bash
# Build
cargo build --release -p pwr-server

# Initialize (generates TLS cert, PSK)
./target/release/pwr-server init

# Start the daemon
./target/release/pwr-server start
```

### Client (Laptop — Arch Linux)

```bash
# Build
cargo build --release

# Configure (use the PSK printed by server init)
pwr init --server-host nas.local --psk <hex-key>

# Set up shell integration
eval "$(pwr shell bash)"

# Archive a project
pwr archive ~/Projects/old-project

# Restore — just cd into it
cd ~/Projects/old-project   # auto-restores!

# Or explicitly
pwr restore ~/Projects/old-project

# See status
pwr status

# Launch TUI
pwr tui
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
server_fingerprint = "sha256:..."
local_root = "/home/jacob/Projects"
connect_timeout_secs = 10
transfer_timeout_secs = 300
```

### Server (/etc/pwr/server.toml)

```toml
version = 1
listen_address = "0.0.0.0"
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

## License

MIT
