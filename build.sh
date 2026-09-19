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
echo "  scp $OUT alex:/srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf/com.braedach.zoraxy.cloudflarewaf"
echo "  # first install only: also copy icon.png, and cloudflarewaf.example.json there as cloudflarewaf.json"
echo "  # (the binary MUST be named like its folder or Zoraxy says \"no valid entry point found\";"
echo "  #  restart Zoraxy after the first install - it only scans plugins at startup)"
echo "  # and edit it with real Cloudflare credentials before enabling in the plugin UI"
