import argparse, json, os, re, time, hashlib, urllib.parse
import requests

SAFE_MODULES={"surface","js_routes","auth_boundary","cors","redirects","cache","xss_reflection","sqli_differential"}


def load_cfg(path):
    with open(path,encoding="utf-8") as f: return json.load(f)

def in_scope(url, targets):
    try:
        u=urllib.parse.urlsplit(url)
        for t in targets:
            tt=urllib.parse.urlsplit(t)
            if u.scheme in ("http","https") and u.hostname==tt.hostname:
                return True
    except: pass
    return False

def excluded(url, paths):
    p=urllib.parse.urlsplit(url).path
    return any(p.startswith(x) for x in paths)

def req(method,url,**kw):
    kw.setdefault("timeout",12)
    kw.setdefault("allow_redirects",False)
    headers=kw.pop("headers",{})
    headers.setdefault("User-Agent","BugBounty-AI/1.0 scoped-security-research")
    return requests.request(method,url,headers=headers,**kw)

def add(out,module,target,title,evidence,confidence="candidate"):
    out.append({"module":module,"target":target,"title":title,"evidence":evidence,"confidence":confidence})

def run_surface(base,out,budget):
    for p in ["/","/robots.txt","/.well-known/security.txt"]:
        if budget[0]<=0: break
        u=urllib.parse.urljoin(base,p)
        try:
            r=req("GET",u); budget[0]-=1
            if r.status_code>=500:
                add(out,"surface",u,"Unexpected server error",f"HTTP {r.status_code}, {len(r.content)} bytes")
        except Exception as e: pass

def run_js_routes(base,out,budget):
    if budget[0]<=0:return
    try:r=req("GET",base); budget[0]-=1
    except:return
    scripts=re.findall(r'<script[^>]+src=["\']([^"\']+)',r.text,re.I)
    routes=set(); hosts=set()
    for s in scripts[:20]:
        if budget[0]<=0:break
        u=urllib.parse.urljoin(base,s)
        try:
            x=req("GET",u); budget[0]-=1
            txt=x.text[:4000000]
            routes.update(re.findall(r'["\'](/[^"\']{2,180})["\']',txt))
            hosts.update(re.findall(r'https://[A-Za-z0-9._-]+',txt))
        except: pass
    interesting=[x for x in routes if any(k in x.lower() for k in ("api","auth","account","user","order","payment","admin","token","session"))]
    if interesting:
        add(out,"js_routes",base,"Interesting client-side routes exposed",{"routes":sorted(interesting)[:80],"hosts":sorted(hosts)[:50]},"info")

def run_auth_boundary(base,out,budget):
    paths=["/api","/api/me","/api/user","/api/account","/account","/settings","/admin"]
    for p in paths:
        if budget[0]<=0:break
        u=urllib.parse.urljoin(base,p)
        try:
            r=req("GET",u); budget[0]-=1
            ctype=r.headers.get("content-type","")
            if r.status_code==200 and ("json" in ctype.lower() or any(k in r.text.lower() for k in ("email","account_id","user_id","merchant_id"))):
                add(out,"auth_boundary",u,"Potential unauthenticated sensitive response",f"HTTP 200 content-type={ctype} body-prefix={r.text[:300]}")
        except: pass

def run_cors(base,out,budget):
    if budget[0]<=0:return
    try:
        r=req("GET",base,headers={"Origin":"https://attacker.invalid"}); budget[0]-=1
        acao=r.headers.get("access-control-allow-origin","")
        acc=r.headers.get("access-control-allow-credentials","")
        if acao=="https://attacker.invalid" and acc.lower()=="true":
            add(out,"cors",base,"Credentialed arbitrary-origin CORS candidate",f"ACAO={acao}; ACAC={acc}")
    except:pass

def run_redirects(base,out,budget):
    for key in ("next","url","redirect","return","continue"):
        if budget[0]<=0:break
        u=base.rstrip("/")+"/?"+key+"="+urllib.parse.quote("https://example.invalid/")
        try:
            r=req("GET",u); budget[0]-=1
            loc=r.headers.get("location","")
            if r.status_code in (301,302,303,307,308) and loc.startswith("https://example.invalid"):
                add(out,"redirects",u,"Open redirect candidate",f"HTTP {r.status_code} Location={loc}")
        except:pass

def run_cache(base,out,budget):
    if budget[0]<2:return
    marker="bbai-"+hashlib.sha1(base.encode()).hexdigest()[:8]
    try:
        a=req("GET",base,headers={"X-Forwarded-Host":marker+".invalid"}); budget[0]-=1
        b=req("GET",base); budget[0]-=1
        if marker in b.text or marker in b.headers.get("location",""):
            add(out,"cache",base,"Possible cache poisoning persistence",f"Marker {marker} persisted into clean request")
    except:pass

def run_xss(base,out,budget):
    if budget[0]<=0:return
    marker="bbai_xss_7391"
    u=base.rstrip("/")+"/?q="+marker
    try:
        r=req("GET",u); budget[0]-=1
        if marker in r.text:
            add(out,"xss_reflection",u,"Input reflection candidate",f"Marker reflected in response; manual context validation required", "candidate")
    except:pass

def run_sqli(base,out,budget):
    if budget[0]<2:return
    try:
        u1=base.rstrip("/")+"/?id=1"
        u2=base.rstrip("/")+"/?id=1%27"
        a=req("GET",u1); budget[0]-=1
        b=req("GET",u2); budget[0]-=1
        err=re.compile(r"sql|syntax error|unterminated|mysql|postgres|sqlite|ora-\d+",re.I)
        if err.search(b.text) and not err.search(a.text):
            add(out,"sqli_differential",u2,"SQL error differential candidate",f"Baseline={a.status_code}/{len(a.content)} mutated={b.status_code}/{len(b.content)}")
    except:pass

FUNCS={"surface":run_surface,"js_routes":run_js_routes,"auth_boundary":run_auth_boundary,"cors":run_cors,"redirects":run_redirects,"cache":run_cache,"xss_reflection":run_xss,"sqli_differential":run_sqli}

ap=argparse.ArgumentParser(); ap.add_argument("--config",required=True); ap.add_argument("--module",required=True); ap.add_argument("--out",required=True); args=ap.parse_args()
cfg=load_cfg(args.config)
if args.module not in cfg.get("enabled_modules",[]):
    raise SystemExit(f"module {args.module} not enabled")
if args.module not in SAFE_MODULES:
    raise SystemExit("module requires an explicit separate aggressive profile")
findings=[]
for base in cfg["targets"]:
    if not in_scope(base,cfg["targets"]) or excluded(base,cfg.get("exclude_paths",[])): continue
    budget=[int(cfg.get("max_requests_per_runner",40))]
    FUNCS[args.module](base,findings,budget)
    time.sleep(int(cfg.get("delay_ms",750))/1000)
os.makedirs(os.path.dirname(args.out) or ".",exist_ok=True)
with open(args.out,"w",encoding="utf-8") as f: json.dump({"module":args.module,"findings":findings},f,indent=2,ensure_ascii=False)
print(json.dumps({"module":args.module,"findings":len(findings)},ensure_ascii=False))
