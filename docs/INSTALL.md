# Installation Guide

## Prerequisites

- **Rust toolchain** (1.75+): Install via [rustup](https://rustup.rs/)
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

## Install from Source (One-Liner)

```bash
cargo install --git https://github.com/alphaonedev/claude-memory.git
```

This builds a release binary and places it in `~/.cargo/bin/claude-memory`.

Or clone and build locally:

```bash
git clone https://github.com/alphaonedev/claude-memory.git
cd claude-memory
cargo install --path .
```

## Binary Download

Pre-built binaries may be available on the [Releases](https://github.com/alphaonedev/claude-memory/releases) page. Download the binary for your platform, make it executable, and move it into your PATH:

```bash
chmod +x claude-memory
sudo mv claude-memory /usr/local/bin/
```

## Systemd Service Setup

Create a systemd unit so the daemon starts automatically.

```bash
sudo tee /etc/systemd/system/claude-memory.service > /dev/null << 'EOF'
[Unit]
Description=Claude Memory Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/claude-memory --db /var/lib/claude-memory/claude-memory.db serve
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=claude_memory=info

# Run as a dedicated user (optional but recommended)
# User=claude-memory
# Group=claude-memory

[Install]
WantedBy=multi-user.target
EOF
```

Create the data directory and enable the service:

```bash
sudo mkdir -p /var/lib/claude-memory
sudo systemctl daemon-reload
sudo systemctl enable --now claude-memory
```

## Verify Installation

```bash
# Check the binary
claude-memory --help

# If running as a daemon, check health
curl http://127.0.0.1:9077/api/v1/health
# Expected: {"status":"ok","service":"claude-memory"}

# Store a test memory
claude-memory store -T "Installation test" -c "It works." --tier short

# Recall it
claude-memory recall "installation"
```

## Uninstall

```bash
# Stop and remove the service (if using systemd)
sudo systemctl stop claude-memory
sudo systemctl disable claude-memory
sudo rm /etc/systemd/system/claude-memory.service
sudo systemctl daemon-reload

# Remove the binary
cargo uninstall claude-memory
# or: sudo rm /usr/local/bin/claude-memory

# Remove the database (WARNING: deletes all memories)
rm -f claude-memory.db claude-memory.db-wal claude-memory.db-shm
# or if using the systemd path:
# sudo rm -rf /var/lib/claude-memory
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CLAUDE_MEMORY_DB` | `claude-memory.db` | Path to the SQLite database file |
| `RUST_LOG` | (none) | Log level filter (e.g., `claude_memory=info,tower_http=info`) |

## Shell Completions

Generate completions for your shell:

```bash
# Bash
claude-memory completions bash > ~/.local/share/bash-completion/completions/claude-memory

# Zsh
claude-memory completions zsh > ~/.zfunc/_claude-memory

# Fish
claude-memory completions fish > ~/.config/fish/completions/claude-memory.fish
```
