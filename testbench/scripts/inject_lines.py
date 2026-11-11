import time, json, datetime, os
LOG=time.strftime('/srv/zoraxy/log/zr_%Y-')+str(int(time.strftime('%m')))+'.log'
HIST='/srv/zoraxy/plugins/com.braedach.zoraxy.cloudflarewaf/zoraxy_actions.jsonl'
cases=[ # (client, path, status, expected)
 ("198.51.100.11","/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",404,"exploit-endpoints"),
 ("198.51.100.12","/_ignition/execute-solution",404,"exploit-endpoints"),
 ("198.51.100.13","/ps-18dad9886074beaa-1904a0-notfound",404,"exploit-endpoints"),
 ("198.51.100.14","/phpinfo.php",200,"php-diagnostics"),
 ("198.51.100.15","/_profiler/phpinfo",200,"php-diagnostics"),
 ("198.51.100.16","/server-status",200,"panel-and-debug"),
 ("198.51.100.17","/___proxy_subdomain_cpanel",404,"panel-and-debug"),
 ("198.51.100.18","/.claude/settings.json",200,"agent-config"),
 ("198.51.100.19","/.git/config",404,"vcs"),
 # controls: must NOT be flagged
 ("198.51.100.21","/about/info.php",200,None),
 ("198.51.100.22","/docs/server-status",200,None),
 ("198.51.100.23","/owner/repo/src/branch/main/.github/workflows/ci.yml",200,None),
 ("198.51.100.24","/robots.txt",200,None),
]
sent={}
for ip,path,st,exp in cases:
    now=datetime.datetime.now()
    line="[%s] [router:host-http] [origin:bench.example.com] [client: %s] [useragent: eros-test] GET %s %d\n"%(now.strftime('%Y-%m-%d %H:%M:%S.%f'),ip,path,st)
    with open(LOG,'a') as f: f.write(line)
    sent[ip]=(time.time(),path,exp)
    time.sleep(0.05)
time.sleep(3)
got={}
for ln in open(HIST):
    try: a=json.loads(ln)
    except Exception: continue
    if a.get('ip','').startswith('198.51.100.'):
        got[a['ip']]=(datetime.datetime.fromisoformat(a['time']).timestamp(),a['reason'],a['result'])
ok=True; lat=[]
for ip,(ts,path,exp) in sent.items():
    g=got.get(ip)
    if exp is None:
        res="not flagged" if g is None else "FLAGGED (wrong): "+g[1]
        if g is not None: ok=False
    else:
        if g is None: res="MISSED"; ok=False
        else:
            d=g[0]-ts; lat.append(d)
            right=("("+exp+")") in g[1]
            if not right: ok=False
            res="%s in %.2fs %s"%(g[1].split(':')[0].replace('sensitive-path probe ',''),d,"" if right else "WRONG LABEL")
    print("%-58s %s"%(path[:58],res))
print("ALL AS EXPECTED" if ok else "PROBLEM")
if lat: print("detection latency from log write: min %.2fs, median %.2fs, max %.2fs"%(min(lat),sorted(lat)[len(lat)//2],max(lat)))
