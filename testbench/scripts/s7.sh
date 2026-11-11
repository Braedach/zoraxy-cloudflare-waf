#!/bin/bash
D=/srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf
ctl(){ curl -s -XPOST 127.0.0.1:9100/_ctl -d "$1" >/dev/null; }
systemctl stop zoraxy-test; cp /srv/zoraxy/cfw-bench /srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf/c.new; mv /srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf/c.new /srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf/com.braedach.zoraxy.cloudflarewaf; /srv/zoraxy/reset.sh
/srv/zoraxy/feed.sh 203.0.113.71 /.env; /srv/zoraxy/feed.sh 203.0.113.72 /.git/config; sleep 6
for a in aaaaaaaaaaaaaaaa1111 bbbbbbbbbbbbbbbb2222 cccccccccccccccc3333; do ctl "{\"account\":\"$a\",\"agelist\":\"zoraxy_cf_waf_blocklist\",\"ageip\":\"203.0.113.71\",\"agedays\":20}"; done
systemctl restart zoraxy-test; sleep 140
/srv/zoraxy/state.sh | grep -E "^(aaaa|bbbb|cccc)"
journalctl -u zoraxy-test --no-pager | grep -i "expiry" | tail -5 | cut -c60-300
tail -1 $D/zoraxy_actions.jsonl | cut -c1-300
