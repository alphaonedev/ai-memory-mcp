#!/bin/sh
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
set -e

REPO="alphaonedev/ai-memory-mcp"
BINARY="ai-memory"
VERSION="latest"

# Checksum-verification bypass. Initialised to 0 HERE, before any argument
# parsing, and set ONLY by the --insecure-skip-checksum flag below -- so an
# exported SKIP_CHECKSUM=1 inherited from the environment can never enable
# it. See the checksum gate near the end of this script for why the bypass
# is deliberately a flag and not an environment variable (#2449).
SKIP_CHECKSUM=0

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    cat <<'USAGE'
Usage: install.sh [OPTIONS]

Install the ai-memory binary from GitHub releases.

Options:
  -h, --help    Show this help message
  --dir DIR     Override install directory (default: ~/.cargo/bin or ~/.local/bin)
  --version VER Install a specific version tag (default: latest)

  --insecure-skip-checksum
                Install WITHOUT verifying the SHA-256 checksum of the
                downloaded archive. This disables the only integrity
                control this installer has. Provided as a flag -- and
                deliberately NOT as an environment variable -- so that
                bypassing verification is a per-invocation, reviewable
                decision that cannot be silently inherited by a whole
                fleet from a base image or CI environment.

Environment variables:
  AI_MEMORY_INSTALL_DIR   Override install directory

Examples:
  curl -fsSL https://raw.githubusercontent.com/alphaonedev/ai-memory-mcp/main/install.sh | sh
  ./install.sh --dir /usr/local/bin
  AI_MEMORY_INSTALL_DIR=~/bin ./install.sh

  # Passing a flag through a piped install needs the `sh -s --` form:
  curl -fsSL https://raw.githubusercontent.com/alphaonedev/ai-memory-mcp/main/install.sh | sh -s -- --dir /usr/local/bin
USAGE
    exit 0
fi

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        # The `[ $# -ge 2 ]` guards matter: without them, a trailing
        # value-taking flag (`install.sh --dir`) shifts past the end and
        # the bottom-of-loop `shift` then trips `set -e` with an opaque
        # low-level shell error instead of a clear message.
        --dir)
            [ $# -ge 2 ] || { echo "Error: --dir requires a directory argument." >&2; exit 1; }
            shift; AI_MEMORY_INSTALL_DIR="$1" ;;
        --version)
            [ $# -ge 2 ] || { echo "Error: --version requires a version argument." >&2; exit 1; }
            shift; VERSION="$1" ;;
        --insecure-skip-checksum) SKIP_CHECKSUM=1 ;;
        *) echo "Unknown option: $1 (try --help)" >&2; exit 1 ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Windows / PowerShell detection
# ---------------------------------------------------------------------------
if [ -n "$PSModulePath" ] || [ -n "$POWERSHELL_DISTRIBUTION_CHANNEL" ]; then
    echo "Error: It looks like you are running inside PowerShell." >&2
    echo "Please use install.ps1 instead:" >&2
    echo "  irm https://raw.githubusercontent.com/$REPO/main/install.ps1 | iex" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Detect OS
# ---------------------------------------------------------------------------
OS="$(uname -s)"
case "$OS" in
    Linux)              os="unknown-linux-gnu" ;;
    Darwin)             os="apple-darwin" ;;
    MINGW*|MSYS*|CYGWIN*) os="pc-windows-msvc" ;;
    *)
        echo "Error: Unsupported OS: $OS" >&2
        echo "Fallback: cargo install ai-memory" >&2
        exit 1
        ;;
esac

# ---------------------------------------------------------------------------
# Detect architecture
# ---------------------------------------------------------------------------
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)   arch="x86_64" ;;
    aarch64|arm64)   arch="aarch64" ;;
    *)
        echo "Error: Unsupported architecture: $ARCH" >&2
        echo "Fallback: cargo install ai-memory" >&2
        exit 1
        ;;
esac

TARGET="${arch}-${os}"

# ---------------------------------------------------------------------------
# File extension
# ---------------------------------------------------------------------------
case "$os" in
    *windows*) EXT="zip" ;;
    *)         EXT="tar.gz" ;;
esac

ASSET="ai-memory-${TARGET}.${EXT}"

# ---------------------------------------------------------------------------
# Install directory: prefer ~/.cargo/bin, fall back to ~/.local/bin
# ---------------------------------------------------------------------------
if [ -n "$AI_MEMORY_INSTALL_DIR" ]; then
    INSTALL_DIR="$AI_MEMORY_INSTALL_DIR"
elif [ -d "$HOME/.cargo/bin" ]; then
    INSTALL_DIR="$HOME/.cargo/bin"
else
    INSTALL_DIR="$HOME/.local/bin"
fi

echo "Detected platform: ${TARGET}"
echo "Installing to:     ${INSTALL_DIR}"

# ---------------------------------------------------------------------------
# Build download URLs
# ---------------------------------------------------------------------------
if [ "$VERSION" = "latest" ]; then
    BASE_URL="https://github.com/${REPO}/releases/latest/download"
else
    BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
fi

RELEASE_URL="${BASE_URL}/${ASSET}"
CHECKSUM_URL="${BASE_URL}/${ASSET}.sha256"

# ---------------------------------------------------------------------------
# Create install directory
# ---------------------------------------------------------------------------
mkdir -p "$INSTALL_DIR"

# ---------------------------------------------------------------------------
# Temp directory with cleanup
# ---------------------------------------------------------------------------
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# ---------------------------------------------------------------------------
# Download helper with exit-code checking
# ---------------------------------------------------------------------------
download() {
    _url="$1"
    _dest="$2"
    _label="$3"

    if command -v curl >/dev/null 2>&1; then
        if ! curl -fsSL "$_url" -o "$_dest" 2>/dev/null; then
            echo "Error: Failed to download ${_label} from:" >&2
            echo "  ${_url}" >&2
            echo "" >&2
            echo "If this is a 404, the release may not exist for your platform." >&2
            echo "Fallback: cargo install ai-memory" >&2
            return 1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if ! wget -q "$_url" -O "$_dest" 2>/dev/null; then
            echo "Error: Failed to download ${_label} from:" >&2
            echo "  ${_url}" >&2
            echo "" >&2
            echo "If this is a 404, the release may not exist for your platform." >&2
            echo "Fallback: cargo install ai-memory" >&2
            return 1
        fi
    else
        echo "Error: curl or wget is required to download files." >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Download binary archive
# ---------------------------------------------------------------------------
echo "Downloading ${ASSET}..."
if ! download "$RELEASE_URL" "$TMPDIR/$ASSET" "$ASSET"; then
    exit 1
fi

# Print binary archive size
FILESIZE=$(wc -c < "$TMPDIR/$ASSET" | tr -d ' ')
if [ "$FILESIZE" -gt 1048576 ] 2>/dev/null; then
    SIZE_MB=$(echo "scale=1; $FILESIZE / 1048576" | bc 2>/dev/null || echo "$FILESIZE bytes")
    echo "Downloaded: ${SIZE_MB} MB"
else
    echo "Downloaded: ${FILESIZE} bytes"
fi

# ---------------------------------------------------------------------------
# Verify the SHA-256 checksum of the downloaded archive.
#
# --- BEGIN checksum gate (#2449) -- fail CLOSED ---
#
# Data-integrity rule: a missing, unfetchable, malformed, or mismatched
# checksum ABORTS the install. Verification that "passes" by doing nothing
# is not verification.
#
# That was the #2449 defect, and it was the NORMAL path rather than an edge
# case: release.yml published no .sha256 asset for these tarballs, so the
# checksum fetch 404'd on every ordinary install, the old warn-and-continue
# branch fired every time, and no install via this script had ever verified
# the binary it installed.
#
# The bypass is a CLI flag ONLY -- deliberately NOT an environment variable.
# An env var can be set once in a base-image layer, a CI provider's env UI,
# or a shell profile, and is then silently inherited fleet-wide forever,
# recreating the fail-open default invisibly. A flag lives in the literal
# invocation and is greppable in every CI transcript and Dockerfile diff.
# SKIP_CHECKSUM is initialised to 0 at the top of this script and set ONLY
# by --insecure-skip-checksum, so an inherited SKIP_CHECKSUM=1 cannot enable
# it. Piped installs pass it through as:
#   curl -fsSL <url> | sh -s -- --insecure-skip-checksum
#
# Scope, stated honestly: the checksum is served from the SAME origin as the
# archive, so this proves INTEGRITY (no corruption, no truncation, no
# mirror/CDN substitution), NOT AUTHENTICITY against a compromised release
# pipeline. Signed build provenance is tracked separately for v1.x.
# ---------------------------------------------------------------------------
is_sha256_hex() {
    _hex="$1"
    [ "${#_hex}" -eq 64 ] || return 1
    case "$_hex" in
        *[!0-9a-f]*) return 1 ;;
    esac
    return 0
}

# Every abort in this gate ends here, so there is exactly ONE machine-
# readable token an operator (or a log scraper, or the gate's own
# self-test) can grep for to prove the refusal was deliberate rather than
# an unrelated crash. A self-test that accepted any non-zero exit as
# "correctly refused" would pass for the wrong reason.
abort_unverified() {
    echo "" >&2
    echo "ai-memory: install aborted (checksum gate #2449)" >&2
    exit 1
}

if [ "$SKIP_CHECKSUM" = "1" ]; then
    # Announced on BOTH streams so a wrapper that captures only one of them
    # still surfaces the bypass in its transcript.
    echo ""
    echo "DANGER: checksum verification bypassed via --insecure-skip-checksum."
    echo "DANGER: the binary being installed is UNVERIFIED."
    echo ""
    echo "DANGER: checksum verification bypassed via --insecure-skip-checksum." >&2
    echo "DANGER: the binary being installed is UNVERIFIED." >&2
else
    echo "Verifying checksum..."

    if ! download "$CHECKSUM_URL" "$TMPDIR/${ASSET}.sha256" "checksum"; then
        echo "Error: could not download the SHA-256 checksum for ${ASSET}:" >&2
        echo "  ${CHECKSUM_URL}" >&2
        echo "" >&2
        echo "Refusing to install an unverified binary." >&2
        echo "Releases cut before v1.0.0 may not publish a .sha256 asset." >&2
        echo "Options:" >&2
        echo "  - install a release that publishes checksums (omit --version for latest)" >&2
        echo "  - build from source:  cargo install ai-memory" >&2
        echo "  - accept the risk explicitly:  install.sh --insecure-skip-checksum" >&2
        abort_unverified
    fi

    EXPECTED_HASH=$(awk 'NR == 1 { print $1 }' "$TMPDIR/${ASSET}.sha256" | tr -d '\r' | tr 'A-F' 'a-f')

    # A 200-response carrying a garbage body (captive portal, proxy error
    # page, truncated transfer) must never be mistaken for a checksum.
    # Before #2449 an empty EXPECTED_HASH fell through the `[ -n ... ]`
    # guard and installed the binary with no message whatsoever -- a
    # second, quieter fail-open in the very same block.
    if ! is_sha256_hex "$EXPECTED_HASH"; then
        echo "Error: the checksum file at" >&2
        echo "  ${CHECKSUM_URL}" >&2
        echo "does not contain a valid SHA-256 digest." >&2
        echo "" >&2
        echo "Refusing to install an unverified binary." >&2
        echo "Fallback: cargo install ai-memory" >&2
        abort_unverified
    fi

    # sha256sum (GNU coreutils) -> shasum (macOS/BSD, Perl) -> openssl.
    # The openssl rung parses the DEFAULT output shape and never passes
    # `-r`: OpenSSL 3 prints "SHA2-256(f)= <hex>" and LibreSSL / OpenSSL
    # 1.1 print "SHA256(f)= <hex>", so the last field is the digest in
    # both. Any parse surprise is caught by the is_sha256_hex check below
    # and fails CLOSED rather than comparing garbage. python3/hashlib is
    # deliberately NOT a rung: an interpreter whose own presence and
    # version are unverified is not a supply-chain integrity tool.
    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL_HASH=$(sha256sum "$TMPDIR/$ASSET" | awk '{ print $1 }')
    elif command -v shasum >/dev/null 2>&1; then
        ACTUAL_HASH=$(shasum -a 256 "$TMPDIR/$ASSET" | awk '{ print $1 }')
    elif command -v openssl >/dev/null 2>&1; then
        ACTUAL_HASH=$(openssl dgst -sha256 "$TMPDIR/$ASSET" | awk '{ print $NF }')
    else
        echo "Error: no SHA-256 tool found on this host." >&2
        echo "Looked for: sha256sum, shasum, openssl." >&2
        echo "" >&2
        echo "Refusing to install an unverified binary." >&2
        echo "Install GNU coreutils, perl, or openssl and re-run." >&2
        echo "Fallback: cargo install ai-memory" >&2
        abort_unverified
    fi

    ACTUAL_HASH=$(printf '%s' "$ACTUAL_HASH" | tr 'A-F' 'a-f')
    if ! is_sha256_hex "$ACTUAL_HASH"; then
        echo "Error: could not compute a SHA-256 digest of ${ASSET}." >&2
        echo "" >&2
        echo "Refusing to install an unverified binary." >&2
        echo "Fallback: cargo install ai-memory" >&2
        abort_unverified
    fi

    if [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
        echo "Error: CHECKSUM MISMATCH -- refusing to install ${ASSET}." >&2
        echo "  Expected: ${EXPECTED_HASH}" >&2
        echo "  Actual:   ${ACTUAL_HASH}" >&2
        echo "" >&2
        echo "The download is corrupt or has been tampered with." >&2
        echo "Do NOT run the downloaded file. Re-run the installer; if the" >&2
        echo "mismatch persists, report it at" >&2
        echo "  https://github.com/${REPO}/issues" >&2
        abort_unverified
    fi

    echo "Checksum OK: ${ACTUAL_HASH}"
fi
# --- END checksum gate (#2449) ---

# ---------------------------------------------------------------------------
# Extract
# ---------------------------------------------------------------------------
echo "Extracting..."
case "$EXT" in
    tar.gz) tar xzf "$TMPDIR/$ASSET" -C "$TMPDIR" ;;
    zip)    unzip -qo "$TMPDIR/$ASSET" -d "$TMPDIR" ;;
esac

# ---------------------------------------------------------------------------
# Validate extracted binary
# ---------------------------------------------------------------------------
if [ ! -f "$TMPDIR/$BINARY" ]; then
    echo "Error: Expected binary '$BINARY' not found after extraction." >&2
    echo "Archive contents:" >&2
    ls -la "$TMPDIR/" >&2
    echo "" >&2
    echo "Fallback: cargo install ai-memory" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Install binary
# ---------------------------------------------------------------------------
cp "$TMPDIR/$BINARY" "$INSTALL_DIR/$BINARY"
chmod +x "$INSTALL_DIR/$BINARY"

if [ ! -x "$INSTALL_DIR/$BINARY" ]; then
    echo "Error: Installed binary is not executable at $INSTALL_DIR/$BINARY" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# macOS: remove Gatekeeper quarantine attribute
# ---------------------------------------------------------------------------
if [ "$OS" = "Darwin" ]; then
    xattr -d com.apple.quarantine "$INSTALL_DIR/$BINARY" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "Installed ${BINARY} to ${INSTALL_DIR}/${BINARY}"

# Verify installation by running the binary
if "$INSTALL_DIR/$BINARY" stats >/dev/null 2>&1; then
    echo "Verification: binary runs successfully."
else
    echo "Installed successfully (could not run 'ai-memory stats' -- database may not be configured yet)."
fi

# Check if install dir is in PATH
case ":$PATH:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
        echo ""
        echo "Note: ${INSTALL_DIR} is not in your PATH."
        echo "Add it with:"
        echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
        ;;
esac

echo ""
echo "Run 'ai-memory --help' to get started."
