#!/bin/sh
# install.sh — one-shot installer for the `iac` binaries.
#
# Detects the host OS + CPU architecture, downloads the matching
# release tarball from GitHub, verifies the SHA-256 checksum, and
# installs every binary the archive ships (CLI everywhere; agent +
# control-plane on Linux; control-plane on macOS / FreeBSD).
#
# Usage (rustup-style one-liner):
#   curl -fsSL https://raw.githubusercontent.com/ASlava12/iac/master/install.sh | sh
#
# Pin a version:
#   curl -fsSL https://.../install.sh | sh -s -- --version v0.0.4
#
# Choose an install prefix:
#   curl -fsSL https://.../install.sh | sh -s -- --prefix /usr/local
#
# Equivalent environment variables:
#   IAC_VERSION         release tag (default: latest)
#   IAC_INSTALL_PREFIX  install directory (default: $HOME/.iac)
#   IAC_REPO            GitHub owner/repo (default: ASlava12/iac)
#   IAC_SKIP_VERIFY=1   skip SHA-256 checksum verification

set -eu

REPO="${IAC_REPO:-ASlava12/iac}"
PREFIX="${IAC_INSTALL_PREFIX:-$HOME/.iac}"
VERSION="${IAC_VERSION:-latest}"
SKIP_VERIFY="${IAC_SKIP_VERIFY:-0}"

err() { printf 'install.sh: error: %s\n' "$*" >&2; exit 1; }
log() { printf 'install.sh: %s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --version) [ $# -ge 2 ] || err "--version needs an argument"
                   VERSION="$2"; shift 2 ;;
        --prefix)  [ $# -ge 2 ] || err "--prefix needs an argument"
                   PREFIX="$2"; shift 2 ;;
        --skip-verify) SKIP_VERIFY=1; shift ;;
        --help|-h)
            cat <<EOF
Usage: install.sh [--version vX.Y.Z] [--prefix DIR] [--skip-verify]

Environment variables:
  IAC_VERSION         release tag (default: latest)
  IAC_INSTALL_PREFIX  install directory (default: \$HOME/.iac)
  IAC_REPO            GitHub repo (default: ASlava12/iac)
  IAC_SKIP_VERIFY=1   skip SHA-256 checksum verification

Examples:
  # Pinned version into /usr/local
  curl -fsSL .../install.sh | sudo sh -s -- --version v0.0.4 --prefix /usr/local

  # Latest into ~/.iac (default)
  curl -fsSL .../install.sh | sh
EOF
            exit 0 ;;
        *) err "unknown argument: $1 (try --help)" ;;
    esac
done

# ---- OS / arch detection -----------------------------------------
uname_s=$(uname -s 2>/dev/null || echo unknown)
uname_m=$(uname -m 2>/dev/null || echo unknown)

case "$uname_s" in
    Linux)   OS=linux ;;
    Darwin)  OS=macos ;;
    FreeBSD) OS=freebsd ;;
    MINGW*|MSYS*|CYGWIN*)
        err "Windows is not supported by this script — download iac-*.zip from https://github.com/${REPO}/releases" ;;
    *) err "unsupported OS: $uname_s" ;;
esac

case "$uname_m" in
    x86_64|amd64)  ARCH=x86_64 ;;
    aarch64|arm64) ARCH=aarch64 ;;
    *) err "unsupported architecture: $uname_m" ;;
esac

# Only OS+arch combos we actually publish artifacts for.
case "${OS}-${ARCH}" in
    linux-x86_64|linux-aarch64|macos-aarch64|freebsd-x86_64) ;;
    *) err "no prebuilt binary for ${OS}-${ARCH} — build from source via 'cargo install --path crates/iac-cli'" ;;
esac

# ---- Resolve version ---------------------------------------------
# GitHub's /releases/latest/download/<file> redirects to the actual
# tag, but the <file> must include the resolved tag in its name —
# our artifacts are versioned. So we resolve "latest" -> "vX.Y.Z"
# up-front via the API.
need_cmd() {
    command -v "$1" >/dev/null 2>&1 || err "missing required command: $1"
}

if command -v curl >/dev/null 2>&1; then
    FETCH="curl -fsSL"
    FETCH_OUT="curl -fsSL -o"
elif command -v wget >/dev/null 2>&1; then
    FETCH="wget -qO-"
    FETCH_OUT="wget -qO"
else
    err "need curl or wget"
fi

if [ "$VERSION" = "latest" ]; then
    log "resolving latest release tag"
    api_url="https://api.github.com/repos/${REPO}/releases/latest"
    # Tolerate jq absence — fall back to a tiny sed extractor.
    if command -v jq >/dev/null 2>&1; then
        VERSION=$($FETCH "$api_url" | jq -r '.tag_name')
    else
        VERSION=$($FETCH "$api_url" \
            | grep -m1 '"tag_name"' \
            | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
    fi
    [ -n "$VERSION" ] && [ "$VERSION" != "null" ] \
        || err "could not resolve latest tag (rate-limited? set IAC_VERSION=vX.Y.Z)"
fi

# Normalise: accept "0.0.4" as well as "v0.0.4".
case "$VERSION" in
    v*) ;;
    *)  VERSION="v${VERSION}" ;;
esac

ARTIFACT="iac-${VERSION}-${OS}-${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARTIFACT}"
SHA_URL="${URL}.sha256"

# ---- Download + verify -------------------------------------------
TMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t iac-install)
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

log "downloading $ARTIFACT"
$FETCH_OUT "$TMPDIR/$ARTIFACT" "$URL" \
    || err "download failed: $URL"

if [ "$SKIP_VERIFY" != "1" ]; then
    log "downloading checksum"
    if $FETCH_OUT "$TMPDIR/$ARTIFACT.sha256" "$SHA_URL" 2>/dev/null; then
        expected=$(awk '{print $1; exit}' "$TMPDIR/$ARTIFACT.sha256")
        if command -v sha256sum >/dev/null 2>&1; then
            actual=$(sha256sum "$TMPDIR/$ARTIFACT" | awk '{print $1}')
        elif command -v shasum >/dev/null 2>&1; then
            actual=$(shasum -a 256 "$TMPDIR/$ARTIFACT" | awk '{print $1}')
        elif command -v sha256 >/dev/null 2>&1; then
            actual=$(sha256 -q "$TMPDIR/$ARTIFACT")
        else
            log "no sha256 tool found; skipping verification"
            actual="$expected"
        fi
        if [ "$expected" != "$actual" ]; then
            err "checksum mismatch: expected $expected, got $actual"
        fi
        log "checksum OK"
    else
        log "checksum file not found, skipping (override with IAC_SKIP_VERIFY=1)"
    fi
fi

# ---- Extract + install -------------------------------------------
log "extracting"
tar -xzf "$TMPDIR/$ARTIFACT" -C "$TMPDIR"
SRCDIR="$TMPDIR/iac-${VERSION}-${OS}-${ARCH}"
[ -d "$SRCDIR" ] || err "expected $SRCDIR inside archive but not found"

mkdir -p "$PREFIX/bin"

installed=""
for bin in iac iac-controlplane iac-agent iac-trial; do
    src="$SRCDIR/$bin"
    if [ -f "$src" ]; then
        cp "$src" "$PREFIX/bin/$bin"
        chmod 0755 "$PREFIX/bin/$bin"
        installed="$installed $bin"
    fi
done

[ -n "$installed" ] || err "no binaries found inside $ARTIFACT"
log "installed:$installed -> $PREFIX/bin/"

# ---- PATH hint ---------------------------------------------------
case ":${PATH:-}:" in
    *":$PREFIX/bin:"*) ;;
    *)
        printf '\n'
        printf 'install.sh: add the following to your shell rc (~/.bashrc, ~/.zshrc, etc.):\n'
        printf '    export PATH="%s/bin:$PATH"\n' "$PREFIX"
        ;;
esac

printf '\n'
log "done. try: $PREFIX/bin/iac --version"
