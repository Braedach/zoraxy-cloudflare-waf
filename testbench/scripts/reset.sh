#!/bin/bash
# reset.sh [config]  -- fresh fake Cloudflare + fresh plugin state, then restart Zoraxy
D=/srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf
systemctl stop zoraxy-test; systemctl stop fakecf
mv -f /srv/zoraxy/fakecf.new /srv/zoraxy/fakecf 2>/dev/null
rm -f $D/zoraxy_actions.jsonl $D/zoraxy_bans.json
cp ${1:-/srv/zoraxy/cfg-bench.json} $D/cloudflarewaf.json; chmod 600 $D/cloudflarewaf.json
systemd-run --unit=fakecf /srv/zoraxy/fakecf -listen 127.0.0.1:9100 -config /srv/zoraxy/accounts.json >/dev/null 2>&1
systemctl start zoraxy-test; sleep 8
