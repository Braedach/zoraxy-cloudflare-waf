#!/bin/bash
D=/srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf
BIN=$D/com.braedach.zoraxy.cloudflarewaf
swap(){ systemctl stop zoraxy-test; install -m 755 "$1" $BIN.new; mv $BIN.new $BIN; }
hist(){ python3 -c '
import json
for l in open("'$D'/zoraxy_actions.jsonl"):
    d=json.loads(l); print("  ",d["ip"],d["result"],"|",d.get("detail","")[:120])'; }
journal(){ journalctl -u zoraxy-test --no-pager --since "$1" | grep -iE "panic|fatal|error|invalid|cannot|failed" | grep -v "Plugin list synced" | cut -c60-260 | head -8; }
for V in A B; do
 echo "################ ROLLBACK VARIANT $V"
 # RC with 3 accounts, as a tester would have it
 swap /srv/zoraxy/cfw-bench; /srv/zoraxy/reset.sh /srv/zoraxy/cfg-bench-sw.json
 /srv/zoraxy/feed.sh 203.0.113.8$([ $V = A ] && echo 1 || echo 5) /.env; sleep 5
 echo "-- RC state before rollback"; hist; /srv/zoraxy/state.sh | grep -E "^(aaaa|bbbb|cccc)"; grep -c additional_targets $D/cloudflarewaf.json
 T=$(date '+%F %T')
 # ---- the documented rollback ----
 systemctl stop zoraxy-test
 install -m 755 /srv/zoraxy/cfw-v035-bench $BIN.new; mv $BIN.new $BIN
 [ $V = B ] && cp -p /srv/zoraxy/cfg-legacy.json $D/cloudflarewaf.json
 systemctl start zoraxy-test; sleep 8
 echo "-- rolled back: $(curl -s 127.0.0.1:8000/api/plugins/list | grep -o 'version_minor":[0-9],"version_patch":[0-9]') active=$(systemctl is-active zoraxy-test)"
 journalctl -u zoraxy-test --no-pager --since "$T" | grep "loaded config" | tail -1 | cut -c60-330
 /srv/zoraxy/feed.sh 203.0.113.9$([ $V = A ] && echo 1 || echo 5) /.git/config; sleep 5
 echo "-- after a new block on v0.3.5"; hist; /srv/zoraxy/state.sh
 echo "-- problems in journal:"; journal "$T"
done
