import argparse, json, os, re, socket, urllib.parse
import requests

from titan_v_pro_core import (
    ActionTrace, RequestBudget, ScopeGuard, TITAN_VERSION, build_finding,
    materially_equivalent, response_meta, semantic_similarity, validate_config,
)

PACKS = {
    0: ["surface", "headers", "well_known", "cookie_security"],
    1: ["js_routes", "api_hints", "sourcemaps"],
    2: ["auth_boundary", "method_diff"],
    3: ["cors", "cache"],
    4: ["redirects", "xss_reflection"],
    5: ["sqli_differential", "error_diff", "error_disclosure"],
    6: ["openapi_graphql", "sensitive_files"],
    7: ["dns_http_inventory", "fingerprints"],
    8: ["status_anomaly", "content_type_diff"],
    9: ["path_normalization_diff", "encoding_diff"],
    10: ["header_behavior_diff", "method_consistency"],
    11: ["response_shape_diff", "cache_variance"],
}

UA = f"BugBounty-AI/{TITAN_VERSION.replace(' ', '-')} scoped-security-research"
SQL_ERROR = re.compile(r"sql|syntax error|unterminated|mysql|postgres|sqlite|ora-\d+|sqlstate", re.I)
ERROR_PATTERNS = {
    "python_traceback": re.compile(r"traceback \(most recent call last\)", re.I),
    "stack_trace": re.compile(r"stack trace", re.I),
    "java_dotnet_frame": re.compile(r"at [a-z0-9_.$]+\([^\n]+:\d+\)", re.I),
    "fatal_error": re.compile(r"fatal error:", re.I),
    "unix_web_path": re.compile(r"/var/www/|/srv/www/", re.I),
    "home_path": re.compile(r"/home/[a-z0-9_.-]+/", re.I),
}
SENSITIVE_JSON_KEYS = {"email", "user_id", "userid", "account_id", "accountid", "customer_id", "merchant_id"}


def load_cfg(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


class ScopedClient:
    def __init__(self, guard, budget):
        self.guard = guard
        self.budget = budget
        self._passive_cache = {}

    def request(self, method, url, **kw):
        ok, reason = self.guard.check(url)
        if not ok:
            self.budget.blocked += 1
            raise ValueError(f"scope_blocked:{reason}:{url}")
        self.budget.consume()
        kw.setdefault("timeout", 12)
        kw.setdefault("allow_redirects", False)
        headers = dict(kw.pop("headers", {}) or {})
        headers.setdefault("User-Agent", UA)
        try:
            return requests.request(method, url, headers=headers, **kw)
        except Exception:
            self.budget.errors += 1
            raise

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def get_cached(self, url):
        if url in self._passive_cache:
            return self._passive_cache[url]
        r = self.get(url)
        self._passive_cache[url] = r
        return r

    def head(self, url, **kw):
        return self.request("HEAD", url, **kw)

    def options(self, url, **kw):
        return self.request("OPTIONS", url, **kw)

    def safe_join(self, base, ref):
        u = self.guard.safe_join(base, ref)
        if not u:
            self.budget.blocked += 1
        return u


def add(out, program, module, target, title, evidence, confidence="candidate", reproducible=False, impact_evidence=False):
    out.append(build_finding(program, module, target, title, evidence, confidence, reproducible, impact_evidence))


def json_key_names(value, limit=300):
    found = set(); stack = [value]; seen = 0
    while stack and seen < limit:
        cur = stack.pop(); seen += 1
        if isinstance(cur, dict):
            for k, v in cur.items():
                found.add(str(k).lower()); stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur[:50])
    return found


def scoped_query(c, base, query):
    p = urllib.parse.urlsplit(base)
    url = urllib.parse.urlunsplit((p.scheme, p.netloc, p.path or "/", query, ""))
    if not c.guard.check(url)[0]:
        c.budget.blocked += 1
        return None
    return url


def scan_surface(program, base, out, c):
    r = c.get(base)
    if r.status_code >= 500:
        add(out, program, "surface", base, "Unexpected server error on scoped base", response_meta(r), "candidate")


def scan_headers(program, base, out, c):
    r = c.head(base)
    h = {k.lower() for k in r.headers}
    missing = [x for x in ("content-security-policy", "strict-transport-security") if x not in h]
    if missing:
        add(out, program, "headers", base, "Security headers absent", {"missing": missing, "status": r.status_code}, "info")


def scan_well_known(program, base, out, c):
    for p in ("/.well-known/security.txt", "/robots.txt"):
        u = c.safe_join(base, p)
        if not u: continue
        try:
            r = c.get(u)
            if p.endswith("security.txt") and r.status_code == 200:
                add(out, program, "well_known", u, "security.txt present", {"status": 200, "bytes": len(r.content)}, "info")
        except Exception:
            pass


def scan_cookie_security(program, base, out, c):
    r = c.get(base)
    raw = r.headers.get("set-cookie", "")
    if not raw: return
    low = raw.lower(); missing = []
    if "secure" not in low: missing.append("Secure")
    if "httponly" not in low: missing.append("HttpOnly")
    if "samesite" not in low: missing.append("SameSite")
    if missing:
        add(out, program, "cookie_security", base, "Cookie security attributes may be incomplete", {"missing": missing, "status": r.status_code}, "info")


def passive_scripts(base, c):
    root = c.get_cached(base)
    refs = re.findall(r'<script[^>]+src=["\']([^"\']+)', root.text, re.I)[:15]
    rows = []
    for ref in refs:
        absolute = urllib.parse.urljoin(base, ref)
        host = urllib.parse.urlsplit(absolute).hostname
        scoped = c.safe_join(base, ref)
        rows.append({"ref": ref, "absolute": absolute, "host": host, "scoped": scoped})
    return rows


def extract_js(program, base, out, c):
    routes, discovered_hosts, fetched = set(), set(), []
    for row in passive_scripts(base, c):
        if row["host"]: discovered_hosts.add(row["host"])
        u = row["scoped"]
        if not u: continue
        try:
            x = c.get_cached(u); fetched.append(u)
            routes.update(re.findall(r'["\'](/[^"\']{2,180})["\']', x.text[:2_000_000]))
        except Exception:
            pass
    interesting = [x for x in routes if any(k in x.lower() for k in ("api", "auth", "account", "user", "order", "payment", "token", "session", "admin", "graphql"))]
    if interesting:
        add(out, program, "js_routes", base, "Interesting client-side routes", {
            "routes": sorted(interesting)[:100],
            "script_hosts_observed": sorted(discovered_hosts)[:50],
            "in_scope_scripts_fetched": len(fetched),
            "third_party_scripts_not_fetched": sum(1 for x in passive_scripts(base, c) if not x["scoped"])
        }, "info")


def scan_sourcemaps(program, base, out, c):
    refs = []
    for row in passive_scripts(base, c):
        u = row["scoped"]
        if not u: continue
        try:
            r = c.get_cached(u)
            for ref in re.findall(r'(?i)sourceMappingURL\s*=\s*([^\s*]+)', r.text[-100000:]):
                absolute = urllib.parse.urljoin(u, ref.strip().strip('"\''))
                in_scope = c.guard.check(absolute)[0]
                refs.append({
                    "script": u,
                    "map_reference": ref[:220],
                    "map_url_in_scope": in_scope,
                    "map_fetched": False
                })
        except Exception:
            pass
    if refs:
        add(out, program, "sourcemaps", base, "Source-map references discovered in in-scope JavaScript", {"references": refs[:30]}, "info")


def scan_api_hints(program, base, out, c):
    for p in ("/api", "/api/v1", "/api/v2"):
        u = c.safe_join(base, p)
        if not u: continue
        try:
            r = c.get(u); ct = r.headers.get("content-type", "")
            if r.status_code == 200 and "json" in ct.lower():
                add(out, program, "api_hints", u, "Public JSON API surface candidate", {"status": 200, "ctype": ct, "bytes": len(r.content)}, "info")
        except Exception:
            pass


def scan_openapi(program, base, out, c):
    for p in ("/openapi.json", "/swagger.json", "/graphql"):
        u = c.safe_join(base, p)
        if not u: continue
        try:
            r = c.get(u); ct = r.headers.get("content-type", "")
            looks_json = "json" in ct.lower() or r.text.lstrip().startswith(("{", "["))
            if r.status_code == 200 and (looks_json or p == "/graphql"):
                add(out, program, "openapi_graphql", u, "Public API schema or GraphQL surface candidate", {
                    "status": 200, "ctype": ct, "bytes": len(r.content), "body_stored": False
                }, "info")
        except Exception:
            pass


def scan_auth(program, base, out, c):
    for p in ("/api/me", "/api/user", "/api/account", "/account", "/settings", "/admin"):
        u = c.safe_join(base, p)
        if not u: continue
        try:
            r = c.get(u); ct = r.headers.get("content-type", "")
            if r.status_code != 200: continue
            keys = set()
            if "json" in ct.lower():
                try: keys = json_key_names(r.json())
                except Exception: pass
            sensitive_names = sorted(keys & SENSITIVE_JSON_KEYS)
            if sensitive_names:
                add(out, program, "auth_boundary", u, "Potential unauthenticated account-shaped response", {
                    "status": 200,
                    "ctype": ct,
                    "sensitive_key_names_only": sensitive_names,
                    "body_values_stored": False
                }, "candidate")
        except Exception:
            pass


def scan_method_diff(program, base, out, c):
    a = c.get(base); o = c.options(base)
    allow = o.headers.get("allow", "")
    if allow:
        add(out, program, "method_diff", base, "Allowed methods advertised", {"get_status": a.status_code, "options_status": o.status_code, "allow": allow}, "info")


def scan_cors(program, base, out, c):
    r = c.get(base, headers={"Origin": "https://attacker.invalid"})
    a = r.headers.get("access-control-allow-origin", "")
    cred = r.headers.get("access-control-allow-credentials", "")
    if a == "https://attacker.invalid" and cred.lower() == "true":
        add(out, program, "cors", base, "Credentialed arbitrary-origin CORS candidate", {"acao": a, "acac": cred, "status": r.status_code}, "candidate", reproducible=True)


def scan_cache(program, base, out, c):
    a = c.get(base, headers={"Cache-Control": "no-cache"}); z = c.get(base)
    ha = {k.lower(): v for k, v in a.headers.items()}; hz = {k.lower(): v for k, v in z.headers.items()}
    keys = ("age", "x-cache", "cf-cache-status", "etag", "cache-control")
    diff = {k: [ha.get(k), hz.get(k)] for k in keys if ha.get(k) != hz.get(k)}
    if diff:
        add(out, program, "cache", base, "Cache behavior differs between no-cache and normal request", {"header_differences": diff}, "info")


def scan_redirect(program, base, out, c):
    for key in ("next", "url", "redirect", "return", "continue"):
        u = scoped_query(c, base, key + "=" + urllib.parse.quote("https://example.invalid/"))
        if not u: continue
        try:
            r = c.get(u); loc = r.headers.get("location", "")
            if r.status_code in (301, 302, 303, 307, 308) and loc.startswith("https://example.invalid"):
                add(out, program, "redirects", u, "Open redirect candidate", {"status": r.status_code, "location": loc}, "candidate", reproducible=True, impact_evidence=True)
        except Exception:
            pass


def scan_xss(program, base, out, c):
    marker = "bbai_xss_7391"; u = scoped_query(c, base, "q=" + marker)
    if not u: return
    r = c.get(u)
    if marker not in r.text: return
    attr = bool(re.search(r'["\'][^"\']*' + re.escape(marker) + r'[^"\']*["\']', r.text, re.I))
    script = bool(re.search(r'<script\b[^>]*>[^<]*' + re.escape(marker), r.text, re.I | re.S))
    add(out, program, "xss_reflection", u, "Input reflection observed", {
        "marker_reflected": True,
        "attribute_context_possible": attr,
        "script_context_possible": script,
        "special_char_execution_not_tested": True
    }, "candidate" if script else "info", reproducible=True, impact_evidence=script)


def scan_sqli(program, base, out, c):
    u1 = scoped_query(c, base, "id=1"); u2 = scoped_query(c, base, "id=1%27")
    if not u1 or not u2: return
    a = c.get(u1); z = c.get(u2)
    if SQL_ERROR.search(z.text) and not SQL_ERROR.search(a.text):
        add(out, program, "sqli_differential", base, "Database error differential candidate", {
            "baseline": response_meta(a), "mutated": response_meta(z), "database_error_marker": True
        }, "candidate")


def scan_error_diff(program, base, out, c):
    a = c.get(base); u = scoped_query(c, base, "__bbai=%00")
    if not u: return
    z = c.get(u)
    if z.status_code >= 500 and a.status_code < 500:
        add(out, program, "error_diff", base, "Malformed-input server error candidate", {"baseline": response_meta(a), "mutated": response_meta(z)}, "candidate")


def scan_error_disclosure(program, base, out, c):
    r = c.get(base); text = r.text[:500000]
    categories = sorted(name for name, rx in ERROR_PATTERNS.items() if rx.search(text))
    if categories:
        add(out, program, "error_disclosure", base, "Potential server-side error detail disclosure", {
            "signature_categories": categories,
            "status": r.status_code,
            "literal_paths_or_values_stored": False
        }, "candidate")


def scan_sensitive(program, base, out, c):
    checks = {
        "/.git/HEAD": lambda t: t.lstrip().startswith("ref: refs/"),
        "/.env": lambda t: bool(re.search(r'(?m)^[A-Z][A-Z0-9_]{2,}\s*=\s*[^\s#]+', t[:10000])),
        "/server-status": lambda t: "Apache Server Status" in t or "Server Version:" in t,
    }
    for p, signature in checks.items():
        u = c.safe_join(base, p)
        if not u: continue
        try:
            r = c.get(u, headers={"Range": "bytes=0-4095"})
            if r.status_code in (200, 206) and signature(r.text):
                add(out, program, "sensitive_files", u, "Sensitive resource signature exposed", {
                    "status": r.status_code,
                    "bytes_received": len(r.content),
                    "range_requested": "0-4095",
                    "signature_confirmed": True,
                    "body_stored": False
                }, "candidate", reproducible=True, impact_evidence=True)
        except Exception:
            pass


def scan_dns(program, base, out, c):
    h = urllib.parse.urlsplit(base).hostname
    try:
        ips = sorted({x[4][0] for x in socket.getaddrinfo(h, 443, type=socket.SOCK_STREAM)})
        add(out, program, "dns_http_inventory", base, "Resolved target inventory", {"ips": ips}, "info")
    except Exception:
        pass


def scan_fingerprint(program, base, out, c):
    r = c.get(base)
    fp = {k: v for k, v in r.headers.items() if k.lower() in ("server", "x-powered-by", "via")}
    if fp:
        add(out, program, "fingerprints", base, "Technology fingerprint", fp, "info")


def scan_status_anomaly(program, base, out, c):
    urls = [base, scoped_query(c, base, "titan_probe=1"), scoped_query(c, base, "titan_probe=2")]
    urls = [x for x in urls if x]
    if len(urls) < 3: return
    rs = [c.get(u) for u in urls]; sts = [r.status_code for r in rs]
    if len(set(sts)) > 1 and 500 in sts:
        add(out, program, "status_anomaly", base, "Unexpected status instability under benign inputs", {"statuses": sts}, "candidate")


def scan_content_type_diff(program, base, out, c):
    u = scoped_query(c, base, "format=json")
    if not u: return
    a = c.get(base); z = c.get(u)
    ca = a.headers.get("content-type", "").split(";")[0]; cz = z.headers.get("content-type", "").split(";")[0]
    if a.status_code == z.status_code == 200 and ca and cz and ca != cz:
        add(out, program, "content_type_diff", base, "Content-type changes under benign query variation", {"baseline": ca, "variant": cz}, "info")


def scan_path_norm(program, base, out, c):
    p = urllib.parse.urlsplit(base); raw = p.path or "/"
    variants = [
        base,
        urllib.parse.urlunsplit((p.scheme, p.netloc, raw.rstrip("/") + "//", "", "")),
        urllib.parse.urlunsplit((p.scheme, p.netloc, raw.rstrip("/") + "/./", "", "")),
    ]
    variants = [u for u in variants if c.guard.check(u)[0]]
    if len(variants) < 2: return
    rs = [c.get(u) for u in variants]; metas = [response_meta(r) for r in rs]
    sig = [(m["status"], m["ctype"], m["structure"]) for m in metas]
    if len({json.dumps(x, sort_keys=True) for x in sig}) > 1 and any(r.status_code < 400 for r in rs):
        add(out, program, "path_normalization_diff", base, "Path normalization produces material response difference", {"variants": metas}, "candidate")


def scan_encoding_diff(program, base, out, c):
    literal = scoped_query(c, base, "q=A"); encoded = scoped_query(c, base, "q=%41")
    if not literal or not encoded: return
    a1 = c.get(literal); z = c.get(encoded); a2 = c.get(literal)
    eq_cross, cross = materially_equivalent(a1, z); eq_repeat, repeat = materially_equivalent(a1, a2)
    if eq_cross: return
    cross_sim = cross["semantic_similarity"]; repeat_sim = repeat["semantic_similarity"]
    correlated = eq_repeat and cross_sim < 0.995 and (repeat_sim - cross_sim) > 0.003
    if correlated:
        add(out, program, "encoding_diff", base, "Equivalent encodings produce reproducibly different semantic responses", {
            "literal_vs_encoded": cross,
            "literal_repeat": repeat,
            "correlated_with_encoding": True
        }, "candidate", reproducible=True)


def scan_header_behavior(program, base, out, c):
    a = c.get(base); z = c.get(base, headers={"Accept": "application/json"})
    if a.status_code == z.status_code and a.headers.get("content-type", "") != z.headers.get("content-type", ""):
        add(out, program, "header_behavior_diff", base, "Response varies by Accept header", {"baseline": response_meta(a), "variant": response_meta(z)}, "info")


def scan_method_consistency(program, base, out, c):
    g = c.get(base); h = c.head(base)
    if g.status_code < 400 and h.status_code >= 500:
        add(out, program, "method_consistency", base, "HEAD/GET consistency anomaly", {"get": g.status_code, "head": h.status_code}, "candidate")


def scan_response_shape(program, base, out, c):
    urls = [scoped_query(c, base, "titan_shape=1"), scoped_query(c, base, "titan_shape=2"), scoped_query(c, base, "titan_shape=3")]
    urls = [x for x in urls if x]
    if len(urls) < 3: return
    rs = [c.get(u) for u in urls]; sizes = [len(r.content) for r in rs]
    sims = [semantic_similarity(rs[0].text, x.text) for x in rs[1:]]
    if max(sizes) - min(sizes) > 100000 and min(sims or [1.0]) < 0.90 and len(set(r.status_code for r in rs)) == 1:
        add(out, program, "response_shape_diff", base, "Large semantic response-shape variance under benign inputs", {"sizes": sizes, "similarities": sims}, "candidate")


def scan_cache_variance(program, base, out, c):
    a = c.get(base, headers={"Cache-Control": "no-cache"}); z = c.get(base)
    va = {k.lower(): v for k, v in a.headers.items()}; vz = {k.lower(): v for k, v in z.headers.items()}
    keys = ("age", "x-cache", "cf-cache-status", "etag")
    diff = {k: [va.get(k), vz.get(k)] for k in keys if va.get(k) != vz.get(k)}
    if diff:
        add(out, program, "cache_variance", base, "Cache metadata variance observed", diff, "info")


FUNCS = {
    "surface": scan_surface,
    "headers": scan_headers,
    "well_known": scan_well_known,
    "cookie_security": scan_cookie_security,
    "js_routes": extract_js,
    "api_hints": scan_api_hints,
    "sourcemaps": scan_sourcemaps,
    "auth_boundary": scan_auth,
    "method_diff": scan_method_diff,
    "cors": scan_cors,
    "cache": scan_cache,
    "redirects": scan_redirect,
    "xss_reflection": scan_xss,
    "sqli_differential": scan_sqli,
    "error_diff": scan_error_diff,
    "error_disclosure": scan_error_disclosure,
    "openapi_graphql": scan_openapi,
    "sensitive_files": scan_sensitive,
    "dns_http_inventory": scan_dns,
    "fingerprints": scan_fingerprint,
    "status_anomaly": scan_status_anomaly,
    "content_type_diff": scan_content_type_diff,
    "path_normalization_diff": scan_path_norm,
    "encoding_diff": scan_encoding_diff,
    "header_behavior_diff": scan_header_behavior,
    "method_consistency": scan_method_consistency,
    "response_shape_diff": scan_response_shape,
    "cache_variance": scan_cache_variance,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--runner", type=int, required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(); cfg = load_cfg(args.config); rid = args.runner
    if rid not in PACKS: raise SystemExit("runner must be 0..11")
    errors = validate_config(cfg)
    if errors: raise SystemExit("invalid TITAN V PRO config: " + "; ".join(errors))

    findings, actions = [], []
    enabled = set(cfg.get("enabled_modules", []))
    delay_ms = int(cfg.get("delay_ms", 1000)); max_req = int(cfg.get("max_requests_per_target_per_runner", 30))

    for prog in cfg.get("programs", []):
        name = prog.get("name", "unknown"); guard = ScopeGuard(prog)
        for base in prog.get("targets", []):
            if not guard.check(base)[0]: continue
            budget = RequestBudget(max_req, delay_ms); client = ScopedClient(guard, budget)
            for mod in PACKS[rid]:
                if mod not in enabled: continue
                trace = ActionTrace(name, base, mod, requests_before=budget.used, findings_before=len(findings), blocked_urls=budget.blocked)
                try:
                    FUNCS[mod](name, base, findings, client)
                except RuntimeError as e:
                    trace.error = str(e)
                    trace.blocked_urls = max(0, budget.blocked - trace.blocked_urls)
                    actions.append(trace.finish(budget, findings))
                    if "budget" in str(e): break
                    continue
                except Exception as e:
                    trace.error = type(e).__name__ + ":" + str(e)[:160]
                trace.blocked_urls = max(0, budget.blocked - trace.blocked_urls)
                actions.append(trace.finish(budget, findings))

    payload = {
        "titan_version": TITAN_VERSION,
        "runner": rid,
        "pack": PACKS[rid],
        "findings": findings,
        "actions": actions,
        "stats": {
            "findings": len(findings),
            "actions": len(actions),
            "requests_used": sum(x.get("requests_used", 0) for x in actions),
            "scope_blocks": sum(x.get("blocked_urls", 0) for x in actions),
            "action_errors": sum(1 for x in actions if x.get("error")),
        },
    }
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(json.dumps({"runner": rid, "pack": PACKS[rid], "findings": len(findings), "actions": len(actions), "titan_version": TITAN_VERSION}, ensure_ascii=False))


if __name__ == "__main__":
    main()
