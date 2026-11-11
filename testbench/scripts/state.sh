#!/bin/bash
curl -s 127.0.0.1:9100/_state | python3 -c '
import json,sys
d=json.load(sys.stdin)
for a,v in sorted(d.items()):
    print(a[:4], "fail=%s"%v["fail"], {n:l["items"] for n,l in v["lists"].items()})
    for z,r in v["zones"].items():
        print("   ",z[:12], [(x["action"],x["expression"],x["description"][:20]) for x in (r or [])])
'
