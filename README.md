# Psync

Archive projects from your laptop to a NAS, restore them when you need them
back. Like rsync but the server never sees your data — everything is encrypted
on the client with age before it leaves the machine.

Linux only. Uses systemd for the daemon and a handful of Linux-specific APIs
under the hood.

## How it works

You run `pwr-server` on your NAS and `pwr` on your laptop. They talk over TLS
1.3 with certificate pinning and PSK-based auth. Before anything leaves the
client, it gets encrypted with age (X25519). The server just stores ciphertext
and serves it back on request — it has no way to decrypt anything.

When you archive a project, pwr tars it, encrypts the tarball, uploads it, and
replaces the directory with a tiny `.project.toml` placeholder. If you set up
the shell hook, `cd`-ing into that directory auto-restores it.

## Quick start

You need Rust (install via [rustup.rs](https://rustup.rs)) and a Linux box.
Run the server on your NAS and the client on your laptop. To kick the tires,
run both on one machine with `localhost` as the host.

### Install

```bash
cargo install pwr-cli
cargo install pwr-server
```

The TUI is included by default. Skip it with `--no-default-features` if you
only want the CLI.

### Server

```bash
pwr-server init --with-service
```

This generates a TLS cert, a PSK, a config file, and a systemd unit — all in
one shot. It prints the PSK at the end; save it, you'll give it to the client.

As root it installs a system-wide service. As a normal user everything lives
under `~/.config/pwr/`.

```bash
systemctl --user enable --now pwr-server    # user install
sudo systemctl enable --now pwr-server      # root install
```

If you want the user service to start at boot rather than login:

```bash
sudo loginctl enable-linger $USER
```

### Client

```bash
pwr init --server-host nas.local --psk <hex-key-from-server-init>
```

This writes `~/.config/pwr/config.toml`. Use `localhost` if you're testing on
one machine.

### Use it

```bash
pwr create ~/my-project
pwr archive ~/my-project     # encrypt, upload, free disk space
pwr restore ~/my-project     # pull it back when you need it
pwr status                   # see everything
pwr tui                      # browse with the terminal UI
```

## Shell integration

```bash
pwr shell bash   # prints a hook for ~/.bashrc
pwr shell zsh    # same for zsh
pwr shell fish   # same for fish
```

With the hook installed, `cd`-ing into an archived project auto-restores it.

## Commands

### Client (`pwr`)

| Command | What it does |
|---|---|
| `pwr init` | Create client config |
| `pwr create <path>` | Start tracking a project |
| `pwr archive <path>` | Encrypt and upload, leave a placeholder |
| `pwr restore <path>` | Download, decrypt, and extract |
| `pwr ensure <path>` | Make sure a project is local (used by the cd hook) |
| `pwr status` | Table of all tracked projects and their state |
| `pwr list` | Projects with paths |
| `pwr log` | Transfer history |
| `pwr shell <sh>` | Print shell integration for bash/zsh/fish |
| `pwr tui` | Terminal UI |

### Server (`pwr-server`)

| Command | What it does |
|---|---|
| `pwr-server init [--with-service]` | Generate config, certs, and PSK |
| `pwr-server start [--foreground]` | Start the daemon |
| `pwr-server stop` | Graceful shutdown |
| `pwr-server status` | Health check and config dump |

## Configuration

### Client (`~/.config/pwr/config.toml`)

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

### Server (`/etc/pwr/server.toml`)

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

## Project file format

Each project gets a `.project.toml` in its directory:

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

After archiving, the directory is just that one file. It's the marker the shell
hook watches for.

## Building from source

Needs Rust 1.96+ and OpenSSL/LibreSSL dev headers (ring's dependency).

```bash
git clone https://github.com/jacob/psync
cd psync
cargo build --release
cargo test
```

## Platform support

Linux only, on x86_64 and aarch64. Both IPv4 and IPv6 work — the server binds
dual-stack (`[::]`) and falls back to `0.0.0.0` if IPv6 isn't available. The
client tries v6 addresses first, then v4.

The server and client use libc (daemonization, signal handling, socket ops),
systemd (service management), and Unix permission bits (locking down key
files). These aren't gated behind platform features — they're just how the
code works, so porting to macOS or Windows would be a significant effort. A
macOS client-only build (no TUI, no daemon) might be feasible, but it's not
something I'm working on.

## License

MIT
