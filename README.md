# Psync — Lazy Project Archiver (`pwr`)

A Rust tool that archives projects from your laptop to a NAS and restores
them on demand via `cd`. Uses rsync for reliable, resumable file transfers.

## How it works

1. **Track** a project with `pwr archive <path>` — it uploads to the NAS and
   replaces the local directory with a lightweight `.project.toml` placeholder.
2. **Restore** with `pwr restore <path>` or just `cd` into the directory if
   shell integration is enabled.
3. **Status** with `pwr status` shows all tracked projects and their state.
4. **Log** with `pwr log` to see the transaction history.

## Architecture

```
pwr-core/     — Library: metadata types, config, .project.toml read/write,
                transaction logging, project discovery
pwr-cli/      — Binary: CLI (clap), rsync wrapper with progress bars,
                shell integration (bash/zsh/fish), colored terminal output
```

## Quick start

```bash
# Build
cargo build --release

# Configure (one-time)
pwr init \
  --nas-host mynas \
  --nas-user jacob \
  --nas-base-path /srv/projects \
  --local-root ~/Projects

# Archive a project
pwr archive ~/Projects/old-project

# Restore it explicitly
pwr restore ~/Projects/old-project

# Or: set up shell integration so `cd` restores automatically
eval "$(pwr shell bash)"
cd ~/Projects/old-project   # auto-restores!

# See what's tracked
pwr status
pwr status --recursive

# List all tracked projects
pwr list

# View transaction history
pwr log
pwr log --errors             # show failed transaction details
pwr log old-project          # filter by project name
```

## Commands

| Command | Description |
|---------|-------------|
| `pwr init` | Set up config (`~/.config/pwr/config.toml`) |
| `pwr archive <path>` | Upload project to NAS, leave placeholder |
| `pwr restore <path>` | Download project from NAS |
| `pwr ensure <path>` | Ensure project is local (for shell wrapper) |
| `pwr status` | Show all tracked projects with state |
| `pwr list` | List all tracked projects with paths |
| `pwr log` | View transaction history |
| `pwr shell <shell>` | Generate shell integration (bash/zsh/fish) |

## Project file format (`.project.toml`)

```toml
version = 1
uuid = "0d1cb5b7-1234-4abc-9def-0123456789ab"
name = "myproject"
local_path = "/home/jacob/Projects/myproject"
remote_path = "nas:/srv/projects/myproject"
size_bytes = 14531252221
last_sync = "2026-07-04T18:23:12Z"
compression = false
state = "archived"
```

After archiving, the directory still exists but contains only `.project.toml`,
so editors, bookmarks, and scripts keep working.

## Safety

- rsync is never called with `--delete` by default
- All archive/restore operations are logged to `~/.config/pwr/transactions.log`
- Interrupted operations leave "started" records visible in `pwr log`
- The `.project.toml` placeholder preserves project identity (UUID)
- Dry-run mode available: `pwr archive --dry-run` / `pwr restore --dry-run`
- Local files are only removed AFTER rsync completes successfully

## Shell integration

The `cd` wrapper checks for `.project.toml` and auto-restores archived projects:

```bash
# Bash
eval "$(pwr shell bash)"

# Zsh
eval "$(pwr shell zsh)"

# Fish
pwr shell fish | source
```

## Requirements

- Rust 1.96+
- rsync 3.x
- SSH access to a NAS (or any rsync-compatible remote)

## Configuration

Stored at `~/.config/pwr/config.toml`:

```toml
version = 1
nas_host = "mynas"
nas_user = "jacob"
nas_base_path = "/srv/projects"
local_root = "/home/jacob/Projects"

[rsync_options]
compress = true
archive = true
delete = false
progress = true
bwlimit = 0
extra_flags = []
```
