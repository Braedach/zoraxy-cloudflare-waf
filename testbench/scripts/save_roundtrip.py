import urllib.request, http.cookiejar, json, re, hashlib
ID="com.braedach.zoraxy.cloudflarewaf"; B="http://127.0.0.1:8000/plugin.ui/%s/"%ID
CFG="/srv/zoraxy/plugins/%s/cloudflarewaf.json"%ID
cj=http.cookiejar.CookieJar(); op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
page=op.open(B,timeout=15).read().decode()
tok=re.search(r'const csrfToken = "([^"]*)"',page).group(1)
print("page ok; RC banner script present:", "RELEASE CANDIDATE" in page or "rcBanner" in page, "| csrf token present:", len(tok)>10)
def get(p): return json.loads(op.open(B+p,timeout=15).read())
def post(p,body):
    r=urllib.request.Request(B+p,data=json.dumps(body).encode(),headers={"Content-Type":"application/json","X-CSRF-Token":tok})
    try:
        resp=op.open(r,timeout=15); return resp.status,resp.read().decode()
    except urllib.error.HTTPError as e: return e.code,e.read().decode()
def disk(): return json.load(open(CFG))
before=disk(); print("keys before:",sorted(before))
tokens_before={"primary":before["cloudflare_api_token"],"t":[t["cloudflare_api_token"] for t in before["additional_targets"]]}
st=get("api/status")["config"]
def payload(**over):
    p=dict(st); p["cloudflare_api_token"]=""             # the UI sends a blank token = keep the stored one
    p["additional_targets"]=[dict(t,cloudflare_api_token="") for t in st.get("additional_targets",[])]
    p.update(over); return p
# 1. valid change
code,body=post("api/config",payload(probe_disabled_categories=["ci-config"],probe_allow_paths=["/myapp/*","/types/credentials.json"]))
print("save with probe change ->",code)
a=disk()
print("  additional_targets kept:",len(a.get("additional_targets",[])),"labels:",[t["label"] for t in a["additional_targets"]],"| extra_zone_ids:",a.get("extra_zone_ids"))
print("  tokens preserved (primary + extra accounts):",a["cloudflare_api_token"]==tokens_before["primary"] and [t["cloudflare_api_token"] for t in a["additional_targets"]]==tokens_before["t"])
print("  probe settings on disk:",a.get("probe_disabled_categories"),a.get("probe_allow_paths"))
# 2. invalid entries are refused and change nothing
h=hashlib.sha256(open(CFG,'rb').read()).hexdigest()
for bad in (["/*"],["myapp/x"],["/a/*/b"]):
    code,body=post("api/config",payload(probe_allow_paths=bad)); print("  invalid",bad,"->",code,body.strip()[:80])
code,body=post("api/config",payload(probe_disabled_categories=["nope"])); print("  invalid category ->",code,body.strip()[:80])
print("  file unchanged by the refused saves:",hashlib.sha256(open(CFG,'rb').read()).hexdigest()==h)
# 3. revert: the probe keys disappear again, the accounts stay
code,body=post("api/config",payload(probe_disabled_categories=[],probe_allow_paths=[]))
c=disk(); print("revert ->",code,"| probe keys on disk:",[k for k in c if k.startswith("probe_")],"| additional_targets:",len(c.get("additional_targets",[])))
print("keys now vs before:",sorted(set(c)-set(before)),"added;",sorted(set(before)-set(c)),"removed")
