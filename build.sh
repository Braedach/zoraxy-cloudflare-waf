#!/bin/bash
# Cross-compiles the plugin for the alex LXC (Debian 13, linux/amd64, bare systemd -
# no container runtime, see Proxmox/LXC/Scripts/setup-lxc-proxy.sh in the homelab repo).
set -euo pipefail
cd "$(dirname "$0")"

VERSION="$(date +%Y.%m.%d)-$(git rev-parse --short HEAD)"
OUT="build/zoraxy-cloudflare-waf_${VERSION}_linux_amd64"

mkdir -p build
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$OUT" .

echo "Built: $OUT"
echo
echo "Install on alex:"
echo "  scp $OUT alex:/srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf/zoraxy-cloudflare-waf"
echo "  # first install only: also copy cloudflarewaf.example.json there as cloudflarewaf.json"
echo "  # and edit it with real Cloudflare credentials before enabling in the plugin UI"
