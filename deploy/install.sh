#!/usr/bin/env bash
# Capa one-line installer for Linux and macOS (Apple Silicon).
#
# Downloads the latest pre-built `capa` binary, drops it into
# ~/.local/bin/capa, and adds that directory to your PATH by
# editing the appropriate shell rc file if it is not already on
# $PATH. The binary bundles Python and the Capa runtime via
# PyInstaller; no Python install is required.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/nelsonduarte/capa-language/main/deploy/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/nelsonduarte/capa-language/main/deploy/install.sh | INSTALL_DIR=/usr/local/bin bash
#
# Set CAPA_NO_MODIFY_PATH=1 to skip the rc edit and only print a
# PATH hint (the old behaviour):
#   curl -fsSL .../install.sh | CAPA_NO_MODIFY_PATH=1 bash
#
# Or run it as a regular shell script after cloning the repo:
#   bash deploy/install.sh
#
# The installer is idempotent: re-running it overwrites the
# existing capa binary with the latest release and never
# duplicates the PATH line in your shell rc.

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
#
# Threat model (audit 2026-05-25 M3): the binary and its .sha256 are
# fetched from the same GitHub release origin over the same TLS-
# protected redirect chain. This catches accidental corruption and an
# attacker who can tamper with the binary blob but NOT the .sha256
# (e.g. a partial CDN cache poisoning). It does NOT defend against an
# adversary who fully controls that origin / redirect chain: such an
# attacker can rewrite both files consistently. Pinning a hash inside
# this script would raise that bar, but it is fundamentally
# incompatible with being the "latest" entry point (the pinned hash
# would have to change every release). Users who need that guarantee
# should install a specific tagged version and verify the GitHub
# build attestation with ``gh attestation verify`` out of band.
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

# PATH setup. If INSTALL_DIR is already on $PATH we do nothing.
# Otherwise we add it by appending to the user's shell rc file,
# detected from $SHELL. Set CAPA_NO_MODIFY_PATH to any non-empty
# value to opt out of the rc edit and fall back to the old hint.
#
# Note: this script runs in a subshell (e.g. via `| bash`), so it
# cannot mutate the parent shell's environment. We edit the rc
# file for future shells and tell the user how to refresh the
# current one.
CAPA_PATH_MARKER="# added by capa-install"

print_path_hint() {
    cat <<EOF
capa-install: $INSTALL_DIR is NOT on your PATH.
              Add this line to your shell rc (~/.bashrc, ~/.zshrc, ~/.config/fish/config.fish):
                  export PATH="\$HOME/.local/bin:\$PATH"
              Then open a new shell and run:
                  capa --version
EOF
}

# Add INSTALL_DIR to the shell rc file. Idempotent: it skips the
# edit if the marker or the directory already appears in the file.
add_to_path() {
    local shell_name rc_file path_line

    shell_name="$(basename -- "${SHELL:-}")"
    case "$shell_name" in
        bash) rc_file="$HOME/.bashrc" ;;
        zsh)  rc_file="$HOME/.zshrc" ;;
        fish) rc_file="$HOME/.config/fish/config.fish" ;;
        *)    rc_file="$HOME/.profile" ;;
    esac

    if [ "$shell_name" = "fish" ]; then
        path_line="fish_add_path \"$INSTALL_DIR\""
    else
        path_line="export PATH=\"$INSTALL_DIR:\$PATH\""
    fi

    # Idempotency guard: bail out if we already wrote this entry.
    # grep returns non-zero when there is no match, which would
    # abort under `set -e`, so swallow its status with `|| true`.
    if [ -f "$rc_file" ] && grep -qF -- "$INSTALL_DIR" "$rc_file" 2>/dev/null; then
        echo "capa-install: $INSTALL_DIR already configured in $rc_file"
        echo "capa-install: open a new shell or run 'source $rc_file' to use capa"
        return 0
    fi

    # Append safely: create the parent directory (needed for fish)
    # and the file if missing, never truncate an existing rc.
    mkdir -p -- "$(dirname -- "$rc_file")"
    {
        printf '\n%s\n' "$CAPA_PATH_MARKER"
        printf '%s\n' "$path_line"
    } >> "$rc_file"

    echo "capa-install: added $INSTALL_DIR to your PATH in $rc_file"
    echo "capa-install: open a new shell or run 'source $rc_file' to use capa"
}

case ":$PATH:" in
    *":$INSTALL_DIR:"*)
        echo "capa-install: $INSTALL_DIR is already on your PATH"
        ;;
    *)
        if [ -n "${CAPA_NO_MODIFY_PATH:-}" ]; then
            print_path_hint
        else
            add_to_path
        fi
        ;;
esac
