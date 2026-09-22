#!/usr/bin/env bash
# Cross-compiles the plugin as a static linux/amd64 binary into ./build/.
#
#   ./build.sh
#
# Needs Go (see go.mod for the version). No cgo, so the binary runs on any linux/amd64 host,
# including minimal containers. Install instructions: see "Setup" in README.md.
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v go >/dev/null 2>&1; then
    echo "error: Go is not installed or not on PATH (see go.mod for the required version)" >&2
    exit 1
fi

# Version stamp for the file name: build date + short commit (or "nogit" outside a git checkout).
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
VERSION="$(date +%Y.%m.%d)-${COMMIT}"
OUT="build/zoraxy-cloudflare-waf_${VERSION}_linux_amd64"

mkdir -p build
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "${OUT}" .

PLUGIN_ID="com.braedach.zoraxy.cloudflarewaf"
echo "Built: ${OUT}"
echo
echo "Install (see README.md -> Setup):"
echo "  copy it into <zoraxy dir>/plugins/<folder>/ and name it exactly like <folder>, e.g."
echo "    <zoraxy dir>/plugins/${PLUGIN_ID}/${PLUGIN_ID}"
echo "  (Zoraxy rejects a binary not named like its folder with \"no valid entry point found\")"
echo "  first install only: also copy icon.png, and cloudflarewaf.example.json as cloudflarewaf.json (chmod 600),"
echo "  then restart Zoraxy and finish the setup in the plugin's own page"
