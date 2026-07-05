# pwr Client Setup Guide (Arch Linux)

## Prerequisites

- Arch Linux
- Rust 1.96+ (install via rustup)
- Network access to the NAS running pwr-server

## Build

```bash
cd /path/to/psync
cargo build --release
sudo cp target/release/pwr /usr/local/bin/
```

For the TUI, build with:

```bash
cargo build --release --features tui
```

## Initialize

Run the init command with the server details and PSK obtained from the
server administrator:

```bash
pwr init \
  --server-host nas.local \
  --server-port 9742 \
  --psk <hex-encoded-psk> \
  --local-root ~/Projects
```

This creates `~/.config/pwr/config.toml` and generates an age identity
at `~/.config/pwr/identity` for at-rest encryption.

## Shell Integration

Add to your `~/.bashrc` (or `~/.zshrc` for Zsh):

```bash
eval "$(pwr shell bash)"
```

For Fish, add to `~/.config/fish/config.fish`:

```fish
pwr shell fish | source
```

After sourcing, `cd` into an archived project directory will
automatically restore it from the server.

## First Archive

```bash
# Track and archive a project
pwr archive ~/Projects/my-rust-project

# Check status
pwr status

# Restore it (or just cd into it with shell integration)
pwr restore ~/Projects/my-rust-project
```

## TUI

Launch the terminal UI for interactive project management:

```bash
pwr tui
```

The TUI provides:
- Project browser with status, size, and sync dates
- Interactive .project.toml creator with form validation
- Transaction log viewer with filtering

## Configuration Reference

`~/.config/pwr/config.toml`:

```toml
version = 2
server_host = "nas.local"
server_port = 9742
server_psk = "hex-encoded-256-bit-key"
server_fingerprint = "sha256:..."  # optional, for cert pinning
local_root = "/home/user/Projects"
connect_timeout_secs = 10
transfer_timeout_secs = 300
```

## Troubleshooting

**No config found**: Run `pwr init` to create the configuration.

**Connection refused**: Verify the server is running on the NAS and the
port is reachable. Check firewall rules.

**Authentication failed**: The PSK in your config does not match the
server's auth_token. Obtain the correct PSK and re-run `pwr init --psk ...`.

**No age identity**: Run `pwr init` to generate the encryption keypair.
Without this, archives cannot be encrypted.
