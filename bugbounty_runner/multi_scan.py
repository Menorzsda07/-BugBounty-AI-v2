import argparse, json, os, re, time, hashlib, urllib.parse, socket
import requests

PACKS = {
  0: ["surface","headers","well_known"],
  1: ["js_routes","api_hints","sourcemaps"],
  2: ["auth_boundary","method_diff"],
  3: ["cors","cache"],
  4: ["redirects","xss_reflection"],
  5: ["sqli_differential","error_diff"],
  6: ["openapi_graphql","sensitive_files"],
  7: ["dns_http_inventory","fingerprints"],
  8: ["status_anomaly","content_type_diff"],
  9: ["path_normalization_diff","encoding_diff"],
  10: ["header_behavior_diff","method_consistency"],
  11: ["response_shape_diff","cache_variance"],
}

UA="BugBounty-AI/3.0 scoped-security-research"

def req(method,url,**kw):
    kw.setdefault("timeout",10); kw.setdefault("allow_redirects",False)
    headers=kw.pop("headers",{}); headers.setdefault("User-Agent",UA)
    return requests.request(method,url,headers=headers,**kw)

def load_cfg(p): return json.load(open(p,encoding="utf-8"))
def excluded(url, excludes):
    path=urllib.parse.urlsplit(url).path or "/"
    return any(path.startswith(x) for x in excludes)
def add(out,program,module,target,title,evidence,confidence="candidate"):
    out.append({"program":program,"module":module,"target":target,"title":title,"evidence":evidence,"confidence":confidence})
def budget_ok(b): return b[0]>0
def get(b,url,**kw):
    if not budget_ok(b): raise RuntimeError("budget")
    b[0]-=1; return req("GET",url,**kw)
def head(b,url,**kw):
    if not budget_ok(b): raise RuntimeError("budget")
    b[0]-=1; return req("HEAD",url,**kw)
def summarize(r):
    return {"status":r.status_code,"bytes":len(r.content),"ctype":r.headers.get("content-type",""),"location":r.headers.get("location","")}

def scan_surface(program,base,out,b):
    try:
        r=get(b,base)
        if r.status_code>=500: add(out,program,"surface",base,"Unexpected server error",f"HTTP {r.status_code}")
    except: pass

def scan_headers(program,base,out,b):
    try:
        r=head(b,base)
        miss=[h for h in ("content-security-policy","strict-transport-security") if h not in {k.lower() for k in r.headers}]
        if miss: add(out,program,"headers",base,"Security headers absent",{"missing":miss},"info")
    except: pass

def scan_well_known(program,base,out,b):
    for p in ("/.well-known/security.txt","/robots.txt"):
        try:get(b,urllib.parse.urljoin(base,p))
        except:pass

def extract_js(program,base,out,b):
    try:r=get(b,base)
    except:return []
    scripts=re.findall(r'<script[^>]+src=["\']([^"\']+)',r.text,re.I)
    urls=[]; routes=set(); maps=[]
    for s in scripts[:15]:
        if not budget_ok(b): break
        u=urllib.parse.urljoin(base,s); urls.append(u)
        try:
            x=get(b,u); txt=x.text[:3000000]
            routes.update(re.findall(r'["\'](/[^"\']{2,180})["\']',txt))
            maps += re.findall(r'sourceMappingURL=([^\s]+)',txt)
        except: pass
    if routes:
        interesting=[x for x in routes if any(k in x.lower() for k in ("api","auth","account","user","order","payment","token","session","admin","graphql"))]
        if interesting: add(out,program,"js_routes",base,"Interesting client routes",{"routes":sorted(interesting)[:100]},"info")
    if maps: add(out,program,"sourcemaps",base,"Source-map references found",{"maps":maps[:50]},"info")
    return urls

def scan_api_hints(program,base,out,b):
    for p in ("/api","/api/v1","/api/v2","/graphql","/openapi.json","/swagger.json"):
        if not budget_ok(b): break
        u=urllib.parse.urljoin(base,p)
        try:
            r=get(b,u); ct=r.headers.get("content-type","")
            if r.status_code==200 and ("json" in ct.lower() or p in ("/graphql","/openapi.json","/swagger.json")):
                add(out,program,"api_hints",u,"Public API surface candidate",f"HTTP 200 content-type={ct}","info")
        except: pass

def scan_auth(program,base,out,b):
    for p in ("/api/me","/api/user","/api/account","/account","/settings","/admin"):
        if not budget_ok(b): break
        u=urllib.parse.urljoin(base,p)
        try:
            r=get(b,u); ct=r.headers.get("content-type",""); body=r.text[:500].lower()
            if r.status_code==200 and ("json" in ct.lower() or any(k in body for k in ("email","user_id","account_id","merchant_id"))):
                add(out,program,"auth_boundary",u,"Potential unauthenticated sensitive response",{"status":200,"ctype":ct,"prefix":r.text[:250]})
        except: pass

def scan_method_diff(program,base,out,b):
    if b[0]<2:return
    try:
        get(b,base); b[0]-=1; o=req("OPTIONS",base)
        allow=o.headers.get("allow","")
        if allow: add(out,program,"method_diff",base,"Allowed methods advertised",allow,"info")
    except: pass

def scan_cors(program,base,out,b):
    try:
        r=get(b,base,headers={"Origin":"https://attacker.invalid"})
        a=r.headers.get("access-control-allow-origin",""); c=r.headers.get("access-control-allow-credentials","")
        if a=="https://attacker.invalid" and c.lower()=="true": add(out,program,"cors",base,"Credentialed arbitrary-origin CORS candidate",{"acao":a,"acac":c})
    except: pass

def scan_cache(program,base,out,b):
    if b[0]<2:return
    marker="bbai-"+hashlib.sha1(base.encode()).hexdigest()[:8]
    try:
        get(b,base,headers={"X-Forwarded-Host":marker+".invalid"}); r=get(b,base)
        if marker in r.text or marker in r.headers.get("location",""): add(out,program,"cache",base,"Possible cache poisoning persistence",marker)
    except: pass

def scan_redirect(program,base,out,b):
    for k in ("next","url","redirect","return","continue"):
        if not budget_ok(b):break
        u=base.rstrip("/")+"/?"+k+"="+urllib.parse.quote("https://example.invalid/")
        try:
            r=get(b,u); loc=r.headers.get("location","")
            if r.status_code in (301,302,303,307,308) and loc.startswith("https://example.invalid"):
                add(out,program,"redirects",u,"Open redirect candidate",loc)
        except:pass

def scan_xss(program,base,out,b):
    if not budget_ok(b):return
    m="bbai_xss_7391"; u=base.rstrip("/")+"/?q="+m
    try:
        r=get(b,u)
        if m in r.text:add(out,program,"xss_reflection",u,"Input reflection candidate","Marker reflected; context validation required")
    except:pass

def scan_sqli(program,base,out,b):
    if b[0]<2:return
    try:
        a=get(b,base.rstrip("/")+"/?id=1"); z=get(b,base.rstrip("/")+"/?id=1%27")
        er=re.compile(r"sql|syntax error|unterminated|mysql|postgres|sqlite|ora-\d+",re.I)
        if er.search(z.text) and not er.search(a.text):add(out,program,"sqli_differential",base,"SQL error differential candidate",{"base":a.status_code,"mut":z.status_code})
    except:pass

def scan_error_diff(program,base,out,b):
    if b[0]<2:return
    try:
        a=get(b,base); z=get(b,base.rstrip("/")+"/?__bbai=%00")
        if z.status_code>=500 and a.status_code<500:add(out,program,"error_diff",base,"Malformed-input server error candidate",{"baseline":a.status_code,"mutated":z.status_code})
    except:pass

def scan_openapi(program,base,out,b): scan_api_hints(program,base,out,b)
def scan_sensitive(program,base,out,b):
    for p in ("/.git/HEAD","/.env","/server-status"):
        if not budget_ok(b):break
        u=urllib.parse.urljoin(base,p)
        try:
            r=get(b,u)
            if r.status_code==200 and len(r.content)>0:add(out,program,"sensitive_files",u,"Potential sensitive file exposed",f"HTTP 200 bytes={len(r.content)}")
        except:pass

def scan_dns(program,base,out,b):
    try:
        h=urllib.parse.urlsplit(base).hostname
        ips=sorted({x[4][0] for x in socket.getaddrinfo(h,443,type=socket.SOCK_STREAM)})
        add(out,program,"dns_http_inventory",base,"Resolved target inventory",{"ips":ips},"info")
    except:pass

def scan_fingerprint(program,base,out,b):
    try:
        r=get(b,base); fp={k:v for k,v in r.headers.items() if k.lower() in ("server","x-powered-by","via")}
        if fp:add(out,program,"fingerprints",base,"Technology fingerprint",fp,"info")
    except:pass

# Novel/anomaly-oriented low-impact differential checks.
def scan_status_anomaly(program,base,out,b):
    if b[0]<3:return
    probes=[base,base.rstrip('/')+'/?titan_probe=1',base.rstrip('/')+'/?titan_probe=2']
    try:
        rs=[get(b,u) for u in probes]
        sts=[r.status_code for r in rs]
        if len(set(sts))>1 and 500 in sts:
            add(out,program,"status_anomaly",base,"Unexpected status instability under benign inputs",{"statuses":sts})
    except: pass

def scan_content_type_diff(program,base,out,b):
    if b[0]<2:return
    try:
        a=get(b,base); z=get(b,base.rstrip('/')+'/?format=json')
        ca=a.headers.get('content-type','').split(';')[0]; cz=z.headers.get('content-type','').split(';')[0]
        if a.status_code==z.status_code==200 and ca and cz and ca!=cz:
            add(out,program,"content_type_diff",base,"Content-type changes under benign query variation",{"baseline":ca,"variant":cz},"info")
    except: pass

def scan_path_norm(program,base,out,b):
    if b[0]<3:return
    try:
        p=urllib.parse.urlsplit(base); root=f"{p.scheme}://{p.netloc}"
        urls=[root+'/',root+'//',root+'/./']
        rs=[get(b,u) for u in urls]
        sig=[(r.status_code,len(r.content),r.headers.get('location','')) for r in rs]
        if len(set(sig))>1 and any(r.status_code<400 for r in rs):
            add(out,program,"path_normalization_diff",base,"Path normalization differential",{"variants":sig},"info")
    except: pass

def scan_encoding_diff(program,base,out,b):
    if b[0]<2:return
    try:
        a=get(b,base.rstrip('/')+'/?q=A'); z=get(b,base.rstrip('/')+'/?q=%41')
        if a.status_code==z.status_code and hashlib.sha256(a.content).hexdigest()!=hashlib.sha256(z.content).hexdigest():
            add(out,program,"encoding_diff",base,"Equivalent input encodings produce different responses",{"a":summarize(a),"encoded":summarize(z)},"info")
    except: pass

def scan_header_behavior(program,base,out,b):
    if b[0]<2:return
    try:
        a=get(b,base); z=get(b,base,headers={'Accept':'application/json'})
        if a.status_code==z.status_code and a.headers.get('content-type','')!=z.headers.get('content-type',''):
            add(out,program,"header_behavior_diff",base,"Response varies materially by Accept header",{"baseline":summarize(a),"variant":summarize(z)},"info")
    except: pass

def scan_method_consistency(program,base,out,b):
    if b[0]<2:return
    try:
        g=get(b,base); b[0]-=1; h=req('HEAD',base)
        if g.status_code<400 and h.status_code>=500:
            add(out,program,"method_consistency",base,"HEAD/GET consistency anomaly",{"get":g.status_code,"head":h.status_code})
    except: pass

def scan_response_shape(program,base,out,b):
    if b[0]<3:return
    try:
        rs=[get(b,base.rstrip('/')+q) for q in ('/?titan_shape=1','/?titan_shape=2','/?titan_shape=3')]
        sizes=[len(r.content) for r in rs]
        if max(sizes)-min(sizes)>200000 and len(set(r.status_code for r in rs))==1:
            add(out,program,"response_shape_diff",base,"Large response-shape variance under benign equivalent inputs",{"sizes":sizes},"info")
    except: pass

def scan_cache_variance(program,base,out,b):
    if b[0]<2:return
    try:
        a=get(b,base,headers={'Cache-Control':'no-cache'}); z=get(b,base)
        va={k.lower():v for k,v in a.headers.items()}; vz={k.lower():v for k,v in z.headers.items()}
        keys=('age','x-cache','cf-cache-status','etag')
        diff={k:[va.get(k),vz.get(k)] for k in keys if va.get(k)!=vz.get(k)}
        if diff:add(out,program,"cache_variance",base,"Cache behavior variance observed",diff,"info")
    except: pass

FUNCS={
"surface":scan_surface,"headers":scan_headers,"well_known":scan_well_known,
"js_routes":lambda p,b,o,bu:extract_js(p,b,o,bu),"api_hints":scan_api_hints,"sourcemaps":lambda p,b,o,bu:extract_js(p,b,o,bu),
"auth_boundary":scan_auth,"method_diff":scan_method_diff,"cors":scan_cors,"cache":scan_cache,
"redirects":scan_redirect,"xss_reflection":scan_xss,"sqli_differential":scan_sqli,"error_diff":scan_error_diff,
"openapi_graphql":scan_openapi,"sensitive_files":scan_sensitive,"dns_http_inventory":scan_dns,"fingerprints":scan_fingerprint,
"status_anomaly":scan_status_anomaly,"content_type_diff":scan_content_type_diff,"path_normalization_diff":scan_path_norm,"encoding_diff":scan_encoding_diff,
"header_behavior_diff":scan_header_behavior,"method_consistency":scan_method_consistency,"response_shape_diff":scan_response_shape,"cache_variance":scan_cache_variance}

ap=argparse.ArgumentParser(); ap.add_argument("--config",required=True); ap.add_argument("--runner",type=int,required=True); ap.add_argument("--out",required=True); args=ap.parse_args()
cfg=load_cfg(args.config); rid=args.runner
if rid not in PACKS: raise SystemExit("runner must be 0..11")
findings=[]
for prog in cfg.get("programs",[]):
    name=prog.get("name","unknown"); excludes=prog.get("exclude_paths",[])
    for base in prog.get("targets",[]):
        if excluded(base,excludes): continue
        budget=[int(cfg.get("max_requests_per_target_per_runner",30))]
        for mod in PACKS[rid]:
            if mod not in cfg.get("enabled_modules",[]): continue
            FUNCS[mod](name,base,findings,budget)
            time.sleep(int(cfg.get("delay_ms",900))/1000)
os.makedirs(os.path.dirname(args.out) or ".",exist_ok=True)
json.dump({"runner":rid,"pack":PACKS[rid],"findings":findings},open(args.out,"w",encoding="utf-8"),indent=2,ensure_ascii=False)
print(json.dumps({"runner":rid,"pack":PACKS[rid],"findings":len(findings)},ensure_ascii=False))
