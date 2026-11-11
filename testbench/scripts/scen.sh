#!/bin/bash
D=/srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf
ctl(){ curl -s -XPOST 127.0.0.1:9100/_ctl -d "$1" >/dev/null; }
last(){ tail -n ${1:-1} $D/zoraxy_actions.jsonl | python3 -c 'import sys,json
for l in sys.stdin:
    d=json.loads(l); print("  ",d["ip"],d["result"],"|",d.get("detail","")[:230])'; }
# install RC
systemctl stop zoraxy-test; cp /srv/zoraxy/cfw-bench $D/c.new; mv $D/c.new $D/com.braedach.zoraxy.cloudflarewaf
echo "== S2: account B returns 403"
/srv/zoraxy/reset.sh; ctl '{"account":"bbbbbbbbbbbbbbbb2222","fail":"403"}'
/srv/zoraxy/feed.sh 203.0.113.31 /.env; sleep 5; last; /srv/zoraxy/state.sh | grep -E "^(aaaa|bbbb|cccc)"
echo "== S3: B recovers, next IP"
ctl '{"account":"bbbbbbbbbbbbbbbb2222","fail":"none"}'; /srv/zoraxy/feed.sh 203.0.113.32 /.git/config; sleep 5; last; /srv/zoraxy/state.sh | grep -E "^(aaaa|bbbb|cccc)"
echo "== S4: someone else's rule with our name already in zone primary-2"
/srv/zoraxy/reset.sh
ctl '{"account":"aaaaaaaaaaaaaaaa1111","seedrule":"x","zone":"zoneprimary000000002","expression":"(http.host eq \"mine.example\")","description":"Zoraxy CF WAF Sync - managed IP blocklist"}'
/srv/zoraxy/feed.sh 203.0.113.41 /.env; sleep 5; last; /srv/zoraxy/state.sh
echo "== S5: account C already has a different list (Free plan = 1 list)"
python3 - <<'PY'
import json
a=json.load(open('/srv/zoraxy/accounts.json')); a['accounts']['cccccccccccccccc3333']['lists']=['customers_other_list']
json.dump(a,open('/srv/zoraxy/accounts-full.json','w'))
PY
systemctl stop zoraxy-test; systemctl stop fakecf; systemd-run --unit=fakecf /srv/zoraxy/fakecf -listen 127.0.0.1:9100 -config /srv/zoraxy/accounts-full.json >/dev/null 2>&1; rm -f $D/zoraxy_actions.jsonl $D/zoraxy_bans.json; systemctl start zoraxy-test; sleep 8
/srv/zoraxy/feed.sh 203.0.113.51 /.env; sleep 5; last; /srv/zoraxy/state.sh | grep -E "^(aaaa|bbbb|cccc)"
echo "== S6: dry run"
sed -i 's/"dry_run": false/"dry_run": true/' /srv/zoraxy/cfg-bench.json; /srv/zoraxy/reset.sh; sed -i 's/"dry_run": true/"dry_run": false/' /srv/zoraxy/cfg-bench.json
N0=$(journalctl -u fakecf --no-pager | wc -l); /srv/zoraxy/feed.sh 203.0.113.61 /.env; sleep 5; last; echo "  fake CF calls during dry run: $(( $(journalctl -u fakecf --no-pager | wc -l) - N0 ))"
echo "== S7: expiry across all accounts"
/srv/zoraxy/reset.sh
/srv/zoraxy/feed.sh 203.0.113.71 /.env; /srv/zoraxy/feed.sh 203.0.113.72 /.git/config; sleep 6
for a in aaaaaaaaaaaaaaaa1111 bbbbbbbbbbbbbbbb2222 cccccccccccccccc3333; do ctl "{\"account\":\"$a\",\"agelist\":\"zoraxy_cf_waf_blocklist\",\"ageip\":\"203.0.113.71\",\"agedays\":20}"; done
/srv/zoraxy/state.sh | grep -E "^(aaaa|bbbb|cccc)"; echo " (restarting plugin to trigger the expiry pass)"
systemctl restart zoraxy-test; sleep 75; /srv/zoraxy/state.sh | grep -E "^(aaaa|bbbb|cccc)"; journalctl -u zoraxy-test --no-pager | grep -i "expir" | tail -4 | cut -c60-300
