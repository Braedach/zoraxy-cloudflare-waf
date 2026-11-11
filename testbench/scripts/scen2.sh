#!/bin/bash
D=/srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf
ctl(){ curl -s -XPOST 127.0.0.1:9100/_ctl -d "$1" >/dev/null; }
inlists(){ curl -s 127.0.0.1:9100/_state | python3 -c '
import json,sys
d=json.load(sys.stdin); ip=sys.argv[1]
print("   ",ip,"in lists of accounts:",[a[:4] for a,v in sorted(d.items()) if any(ip in (l["items"] or []) for l in v["lists"].values())] or "none")' "$1"; }
install_rc(){ systemctl stop zoraxy-test; cp /srv/zoraxy/cfw-bench $D/c.new; mv $D/c.new $D/com.braedach.zoraxy.cloudflarewaf; }
install_rc
echo "== S8: the new families reach every account and zone (live)"
/srv/zoraxy/reset.sh
i=100; for p in /_ignition/execute-solution /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php /phpinfo.php /server-status /___proxy_subdomain_cpanel /.claude/settings.json; do i=$((i+1)); /srv/zoraxy/feed.sh 203.0.113.$i "$p"; done
/srv/zoraxy/feed.sh 203.0.113.120 /about/info.php; /srv/zoraxy/feed.sh 203.0.113.121 /robots.txt
sleep 5
for n in 101 102 103 104 105 106 120 121; do inlists 203.0.113.$n; done
echo "   (expect 101-106 in aaaa,bbbb,cccc; 120 and 121 none)"
echo "== S9: switch off php-diagnostics + never-ban /legit/*"
python3 - <<'PY'
import json
d=json.load(open('/srv/zoraxy/cfg-bench.json'))
d['probe_disabled_categories']=['php-diagnostics']; d['probe_allow_paths']=['/legit/*']
json.dump(d,open('/srv/zoraxy/cfg-bench-sw.json','w'),indent=1)
PY
chmod 600 /srv/zoraxy/cfg-bench-sw.json
/srv/zoraxy/reset.sh /srv/zoraxy/cfg-bench-sw.json
journalctl -u zoraxy-test --no-pager --since "-1 min" | grep -E "WARNING sensitive|probe_categories_off" | sed -E 's/^.*plugin:[0-9]+\] //' | cut -c1-80,330-420 | tail -2
/srv/zoraxy/feed.sh 203.0.113.131 /phpinfo.php; /srv/zoraxy/feed.sh 203.0.113.132 /.git/config; /srv/zoraxy/feed.sh 203.0.113.133 /legit/.env; /srv/zoraxy/feed.sh 203.0.113.134 /_ignition/execute-solution
sleep 5
for n in 131 132 133 134; do inlists 203.0.113.$n; done
echo "   (expect 131 none [family off], 132 banned, 133 none [never-ban], 134 banned)"
echo "== S10: upgrade from a v0.3.x single-account settings file"
cp -p /srv/zoraxy/cfg-v034.json /srv/zoraxy/cfg-v034.orig
python3 -c 'import json;print("   keys before:",sorted(json.load(open("/srv/zoraxy/cfg-v034.json"))))'
/srv/zoraxy/reset.sh /srv/zoraxy/cfg-v034.json
/srv/zoraxy/feed.sh 203.0.113.141 /.env; sleep 5
python3 - <<'PY'
import json
a=json.load(open('/srv/zoraxy/cfg-v034.orig')); b=json.load(open('/srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf/cloudflarewaf.json'))
print("   keys after an upgrade and one block:",sorted(set(b)-set(a)),"added;",sorted(set(a)-set(b)),"removed")
PY
inlists 203.0.113.141
last=$(tail -1 $D/zoraxy_actions.jsonl | python3 -c 'import sys,json;d=json.loads(sys.stdin.read());print(d["result"],"|",d.get("detail","")[:90])'); echo "   last action: $last"
