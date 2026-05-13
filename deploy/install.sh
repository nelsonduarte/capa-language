#!/usr/bin/env bash
# Capa one-line installer for Linux and macOS (Apple Silicon).
#
# Downloads the latest pre-built `capa` binary, drops it into
# ~/.local/bin/capa, and prints a PATH hint if that directory is
# not already on $PATH. The binary bundles Python and the Capa
# runtime via PyInstaller; no Python install is required.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/nelsonduarte/capa/main/deploy/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/nelsonduarte/capa/main/deploy/install.sh | INSTALL_DIR=/usr/local/bin bash
#
# Or run it as a regular shell script after cloning the repo:
#   bash deploy/install.sh
#
# The installer is idempotent: re-running it overwrites the
# existing capa binary with the latest release.

set -euo pipefail

REPO="nelsonduarte/capa"
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
DEST="${INSTALL_DIR}/capa"

echo "capa-install: target  $DEST"
echo "capa-install: source  $URL"

mkdir -p "$INSTALL_DIR"

# Download. Prefer curl, fall back to wget.
if command -v curl >/dev/null 2>&1; then
    curl -fL --progress-bar "$URL" -o "$DEST"
elif command -v wget >/dev/null 2>&1; then
    wget -q --show-progress -O "$DEST" "$URL"
else
    echo "capa-install: neither curl nor wget is available" >&2
    exit 2
fi

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
