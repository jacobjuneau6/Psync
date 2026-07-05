# pwr-server Deployment Guide (Debian 12)

## Prerequisites

- Debian 12 (Bookworm) or later
- Rust 1.96+ (install via rustup)
- OpenSSL development headers: `apt install pkg-config libssl-dev`
- A dedicated user account: `useradd -r -s /bin/false pwr`

## Build

```bash
cd /path/to/psync
cargo build --release -p pwr-server
sudo cp target/release/pwr-server /usr/local/bin/
sudo chmod 755 /usr/local/bin/pwr-server
```

## Initialize

Run the init command to generate TLS certificates, a PSK, and the config file:

```bash
sudo -u pwr pwr-server --config /etc/pwr/server.toml init
```

This creates:
- `/etc/pwr/server.toml` — Server configuration
- `/etc/pwr/server.crt` — Self-signed TLS certificate (ECDSA P-256)
- `/etc/pwr/server.key` — TLS private key (mode 0600)

Note the PSK and certificate fingerprint printed during init. You will need
the PSK for client configuration.

## Configure Storage

Edit `/etc/pwr/server.toml` to set the storage path:

```toml
[storage]
base_path = "/srv/pwr/projects"
max_project_size_gb = 500
```

Create the storage directory:

```bash
sudo mkdir -p /srv/pwr/projects
sudo chown pwr:pwr /srv/pwr/projects
```

## Install systemd Service

```bash
sudo cp pwr-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable pwr-server
sudo systemctl start pwr-server
```

## Verify

```bash
sudo systemctl status pwr-server
sudo journalctl -u pwr-server -f
```

Check that the server is listening:

```bash
ss -tlnp | grep 9742
```

## Firewall

If using nftables or iptables, allow the server port:

```bash
# nftables
nft add rule inet filter input tcp dport 9742 accept

# iptables
iptables -A INPUT -p tcp --dport 9742 -j ACCEPT
```

## Troubleshooting

**Server won't start**: Check that `/etc/pwr/server.toml` exists and the
`auth_token` field is non-empty. Check that the TLS certificate and key
files exist at the paths specified in the config.

**Client can't connect**: Verify the server is listening on the expected
port. Verify the PSK matches between client and server configs. Check
firewall rules.

**Disk full**: The server enforces `max_project_size_gb`. Reduce this
value or free disk space.
