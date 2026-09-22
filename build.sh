#!/usr/bin/env bash
# Cross-compiles the plugin into ./build/.
#
#   ./build.sh                 # linux/amd64 only (default)
#   ./build.sh release         # every architecture published in the GitHub releases
#   ./build.sh arm64 386       # a specific list
#
# Needs Go (see go.mod for the version). No cgo, so the binaries are static. Install: see "Setup" in README.md.
set -euo pipefail
cd "$(dirname "$0")"

# Architectures published in the releases. The asset name is the last segment of the plugin ID plus _linux_<arch>,
# which is what Zoraxy's plugin-store indexer downloads.
RELEASE_ARCHES=(amd64 arm64 arm 386)
PLUGIN_ID="com.braedach.zoraxy.cloudflarewaf"
ASSET_BASE="${PLUGIN_ID##*.}"        # cloudflarewaf

if ! command -v go >/dev/null 2>&1; then
    echo "error: Go is not installed or not on PATH (see go.mod for the required version)" >&2
    exit 1
fi

case "${1:-}" in
    "")        arches=(amd64) ;;
    release)   arches=("${RELEASE_ARCHES[@]}") ;;
    *)         arches=("$@") ;;
esac

# Version stamp for the local file name: build date + short commit (or "nogit" outside a git checkout).
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
VERSION="$(date +%Y.%m.%d)-${COMMIT}"

mkdir -p build
built=()
for arch in "${arches[@]}"; do
    out="build/zoraxy-cloudflare-waf_${VERSION}_linux_${arch}"
    GOOS=linux GOARCH="${arch}" CGO_ENABLED=0 GOARM=7 go build -trimpath -ldflags="-s -w" -o "${out}" .
    built+=("${out}")
    echo "Built: ${out}"
done

if [[ "${1:-}" == "release" ]]; then
    # Release assets: fixed names the store indexer expects, plus checksums.
    rm -rf build/release && mkdir -p build/release
    for arch in "${arches[@]}"; do
        cp "build/zoraxy-cloudflare-waf_${VERSION}_linux_${arch}" "build/release/${ASSET_BASE}_linux_${arch}"
    done
    ( cd build/release && sha256sum ./* > SHA256SUMS )
    echo
    echo "Release assets in build/release/ (upload these, SHA256SUMS included):"
    ls -1 build/release
    exit 0
fi

echo
echo "Install (see README.md -> Setup):"
echo "  copy it into <zoraxy dir>/plugins/<folder>/ and name it exactly like <folder>, e.g."
echo "    <zoraxy dir>/plugins/${PLUGIN_ID}/${PLUGIN_ID}"
echo "  (Zoraxy rejects a binary not named like its folder with \"no valid entry point found\")"
echo "  first install only: also copy icon.png, and cloudflarewaf.example.json as cloudflarewaf.json (chmod 600),"
echo "  then restart Zoraxy and finish the setup in the plugin's own page"
