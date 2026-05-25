#!/usr/bin/env bash
# Capa one-line installer for Linux and macOS (Apple Silicon).
#
# Downloads the latest pre-built `capa` binary, drops it into
# ~/.local/bin/capa, and prints a PATH hint if that directory is
# not already on $PATH. The binary bundles Python and the Capa
# runtime via PyInstaller; no Python install is required.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/nelsonduarte/capa-language/main/deploy/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/nelsonduarte/capa-language/main/deploy/install.sh | INSTALL_DIR=/usr/local/bin bash
#
# Or run it as a regular shell script after cloning the repo:
#   bash deploy/install.sh
#
# The installer is idempotent: re-running it overwrites the
# existing capa binary with the latest release.

set -euo pipefail

REPO="nelsonduarte/capa-language"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

# Resolve the asset for the current platform.
OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
    Linux*)
        case "$ARCH" in
            x86_64|amd64) ASSET="capa-linux-x86_64" ;;
            *) echo "capa-install: unsupported Linux arch '$ARCH'" >&2; exit 2 ;;
        esac
        ;;
    Darwin*)
        case "$ARCH" in
            arm64|aarch64) ASSET="capa-macos-arm64" ;;
            x86_64)
                cat >&2 <<EOF
capa-install: Intel Macs are not shipped as a pre-built binary.
              Install from source:
                  git clone https://github.com/$REPO
                  cd capa
                  pip install -e .
EOF
                exit 2
                ;;
            *) echo "capa-install: unsupported macOS arch '$ARCH'" >&2; exit 2 ;;
        esac
        ;;
    *)
        echo "capa-install: unsupported OS '$OS' (use the Windows installer or install from source)" >&2
        exit 2
        ;;
esac

URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
SHA_URL="${URL}.sha256"
DEST="${INSTALL_DIR}/capa"

echo "capa-install: target  $DEST"
echo "capa-install: source  $URL"

mkdir -p "$INSTALL_DIR"

# Resolve fetch + hash commands once so the download and the
# verify step agree on what is available on this machine.
if command -v curl >/dev/null 2>&1; then
    fetch_bin() { curl -fL --progress-bar "$1" -o "$2"; }
    fetch_text() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch_bin() { wget -q --show-progress -O "$2" "$1"; }
    fetch_text() { wget -q -O - "$1"; }
else
    echo "capa-install: neither curl nor wget is available" >&2
    exit 2
fi

if command -v sha256sum >/dev/null 2>&1; then
    compute_sha() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
    compute_sha() { shasum -a 256 "$1" | awk '{print $1}'; }
else
    echo "capa-install: neither sha256sum nor shasum is available" >&2
    exit 2
fi

# Fetch binary + the .sha256 sibling, then verify before we
# chmod or expose anything. Aborting on mismatch leaves the
# tampered binary on disk so the user can inspect it; remove
# it explicitly first so a re-run starts clean.
fetch_bin "$URL" "$DEST"

EXPECTED_SHA="$(fetch_text "$SHA_URL" | awk '{print $1}')"
if [ -z "$EXPECTED_SHA" ]; then
    echo "capa-install: failed to fetch SHA-256 from $SHA_URL" >&2
    rm -f "$DEST"
    exit 2
fi
ACTUAL_SHA="$(compute_sha "$DEST")"
if [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
    echo "capa-install: SHA-256 mismatch for $ASSET" >&2
    echo "  expected: $EXPECTED_SHA" >&2
    echo "  actual:   $ACTUAL_SHA" >&2
    rm -f "$DEST"
    exit 2
fi
echo "capa-install: sha256  $ACTUAL_SHA (verified)"

chmod +x "$DEST"

# macOS Gatekeeper: strip the quarantine attribute so the
# binary can run without a Settings detour. The flag is harmless
# on Linux (xattr exists but the attribute does not).
if [ "$OS" = "Darwin" ] && command -v xattr >/dev/null 2>&1; then
    xattr -d com.apple.quarantine "$DEST" 2>/dev/null || true
fi

# Verify.
if "$DEST" --version >/dev/null 2>&1; then
    VERSION="$("$DEST" --version)"
    echo "capa-install: installed $VERSION"
else
    echo "capa-install: warning, the binary did not respond to --version" >&2
fi

# PATH hint. We do not modify shell rc files automatically (too
# many shells, too many opinions); we just tell the user what
# line to add when needed.
case ":$PATH:" in
    *":$INSTALL_DIR:"*)
        echo "capa-install: $INSTALL_DIR is already on your PATH"
        ;;
    *)
        cat <<EOF
capa-install: $INSTALL_DIR is NOT on your PATH.
              Add this line to your shell rc (~/.bashrc, ~/.zshrc, ~/.config/fish/config.fish):
                  export PATH="\$HOME/.local/bin:\$PATH"
              Then open a new shell and run:
                  capa --version
EOF
        ;;
esac
