#!/bin/sh
set -e

REPO="alphaonedev/ai-memory-mcp"
BINARY="ai-memory"
INSTALL_DIR="${AI_MEMORY_INSTALL_DIR:-$HOME/.local/bin}"

# Detect OS
OS="$(uname -s)"
case "$OS" in
    Linux)  os="unknown-linux-gnu" ;;
    Darwin) os="apple-darwin" ;;
    MINGW*|MSYS*|CYGWIN*) os="pc-windows-msvc" ;;
    *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)  arch="x86_64" ;;
    aarch64|arm64)  arch="aarch64" ;;
    *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

TARGET="${arch}-${os}"

# Determine file extension
case "$os" in
    *windows*) EXT="zip" ;;
    *)         EXT="tar.gz" ;;
esac

ASSET="ai-memory-${TARGET}.${EXT}"

echo "Detected platform: ${TARGET}"
echo "Installing to: ${INSTALL_DIR}"

# Get latest release URL
RELEASE_URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"

# Create install directory
mkdir -p "$INSTALL_DIR"

# Download and extract
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading ${ASSET}..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$RELEASE_URL" -o "$TMPDIR/$ASSET"
elif command -v wget >/dev/null 2>&1; then
    wget -q "$RELEASE_URL" -O "$TMPDIR/$ASSET"
else
    echo "Error: curl or wget required" >&2
    exit 1
fi

echo "Extracting..."
case "$EXT" in
    tar.gz) tar xzf "$TMPDIR/$ASSET" -C "$TMPDIR" ;;
    zip)    unzip -qo "$TMPDIR/$ASSET" -d "$TMPDIR" ;;
esac

# Install binary
cp "$TMPDIR/$BINARY" "$INSTALL_DIR/$BINARY"
chmod +x "$INSTALL_DIR/$BINARY"

echo ""
echo "Installed ${BINARY} to ${INSTALL_DIR}/${BINARY}"

# Check if install dir is in PATH
case ":$PATH:" in
    *":${INSTALL_DIR}:"*) ;;
    *) echo "Note: Add ${INSTALL_DIR} to your PATH if not already present." ;;
esac

echo "Run 'ai-memory --help' to get started."
