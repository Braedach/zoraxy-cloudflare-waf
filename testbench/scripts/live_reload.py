import urllib.request, http.cookiejar, json, re, time, datetime, os
ID="com.braedach.zoraxy.cloudflarewaf"; B="http://127.0.0.1:8000/plugin.ui/%s/"%ID
HIST="/srv/zoraxy/plugins/%s/zoraxy_actions.jsonl"%ID
LOG=time.strftime('/srv/zoraxy/log/zr_%Y-')+str(int(time.strftime('%m')))+'.log'
cj=http.cookiejar.CookieJar(); op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
tok=re.search(r'const csrfToken = "([^"]*)"',op.open(B,timeout=15).read().decode()).group(1)
st=json.loads(op.open(B+"api/status",timeout=15).read())["config"]
def save(**over):
    p=dict(st); p["cloudflare_api_token"]=""; p["additional_targets"]=[dict(t,cloudflare_api_token="") for t in st.get("additional_targets",[])]; p.update(over)
    r=urllib.request.Request(B+"api/config",data=json.dumps(p).encode(),headers={"Content-Type":"application/json","X-CSRF-Token":tok}); return op.open(r,timeout=15).status
def feed(ip,path):
    now=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
    open(LOG,'a').write("[%s] [router:host-http] [origin:bench.example.com] [client: %s] [useragent: hot-test] GET %s 404\n"%(now,ip,path))
def seen(ip):
    time.sleep(1.5); return any(json.loads(l).get("ip")==ip for l in open(HIST) if l.strip())
print("save (vcs switched OFF) ->",save(probe_disabled_categories=["vcs"]))
feed("198.51.100.201","/.git/config"); feed("198.51.100.202","/.env")
print("  /.git/config (family off) detected:",seen("198.51.100.201"),"| /.env (family on) detected:",seen("198.51.100.202"),"  [expect False, True]")
print("save (vcs back ON) ->",save(probe_disabled_categories=[]))
feed("198.51.100.203","/.git/config"); print("  /.git/config detected again:",seen("198.51.100.203"),"  [expect True]")
