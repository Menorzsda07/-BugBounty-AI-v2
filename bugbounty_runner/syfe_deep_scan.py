import argparse, json, os, re, urllib.parse
from collections import Counter

from multi_scan import ScopedClient, json_key_names
from titan_v_pro_core import RequestBudget, ScopeGuard, TITAN_VERSION, build_finding, validate_config

KEYWORDS = (
    "api", "auth", "login", "session", "token", "user", "account", "profile",
    "portfolio", "order", "trade", "transaction", "payment", "withdraw", "deposit",
    "fund", "kyc", "wallet", "admin", "internal", "graphql", "balance", "holding",
)
PRIVATE_HINTS = (
    "/me", "/user", "/account", "/profile", "/portfolio", "/order", "/trade",
    "/transaction", "/payment", "/withdraw", "/deposit", "/wallet", "/kyc",
    "/admin", "/internal", "/balance", "/holding",
)
ACCOUNT_KEYS = {
    "email", "user_id", "userid", "account_id", "accountid", "customer_id",
    "portfolio", "portfolio_id", "balance", "balances", "holdings", "orders",
    "transactions", "kyc", "phone", "address", "name",
}
STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".map", ".webp", ".mp4", ".pdf",
)
QUOTED_REF = re.compile(r"[\"']((?:https?://[^\"']+|/[^\"']{2,220}))[\"']", re.I)
SCRIPT_SRC = re.compile(r"<script[^>]+src=[\"']([^\"']+)", re.I)


def normalize_candidate(base, ref, guard):
    ref = (ref or "").replace("\\/", "/").strip()
    if not ref or ref.startswith("//"):
        return None
    try:
        url = urllib.parse.urljoin(base, ref)
        p = urllib.parse.urlsplit(url)
        path = p.path or "/"
        if path.lower().endswith(STATIC_EXTENSIONS):
            return None
        low = (path + "?" + p.query).lower()
        if not any(k in low for k in KEYWORDS):
            return None
        clean = urllib.parse.urlunsplit((p.scheme, p.netloc, path, p.query, ""))
        return clean if guard.check(clean)[0] else None
    except Exception:
        return None


def extract_candidates(base, text, guard):
    out = set()
    for ref in QUOTED_REF.findall((text or "")[:2_000_000]):
        u = normalize_candidate(base, ref, guard)
        if u:
            out.add(u)
    return out


def priority(url):
    low = urllib.parse.urlsplit(url).path.lower()
    private = sum(1 for x in PRIVATE_HINTS if x in low)
    keywords = sum(1 for x in KEYWORDS if x in low)
    return (-private, -keywords, len(url), url)


def response_observation(url, r):
    return {
        "url": url,
        "status": r.status_code,
        "ctype": r.headers.get("content-type", ""),
        "location": r.headers.get("location", ""),
        "allow": r.headers.get("allow", ""),
        "bytes": len(r.content),
        "body_stored": False,
    }


def load_cfg(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-endpoints-per-target", type=int, default=10)
    args = ap.parse_args()

    cfg = load_cfg(args.config)
    errors = validate_config(cfg)
    if errors:
        raise SystemExit("invalid TITAN config: " + "; ".join(errors))

    findings = []
    observations = []
    actions = []
    seen_endpoints = set()

    for prog in cfg.get("programs", []):
        name = prog.get("name", "unknown")
        guard = ScopeGuard(prog)
        for base in prog.get("targets", []):
            budget = RequestBudget(
                int(cfg.get("max_requests_per_target_per_runner", 20)),
                int(cfg.get("delay_ms", 1200)),
            )
            client = ScopedClient(guard, budget)
            before = budget.used
            local_candidates = set()
            script_count = 0
            source_count = 0
            error = None

            try:
                root = client.get_cached(base)
                source_count += 1
                local_candidates |= extract_candidates(base, root.text, guard)

                refs = SCRIPT_SRC.findall(root.text)[:10]
                for ref in refs:
                    absolute = urllib.parse.urljoin(base, ref)
                    if not guard.check(absolute)[0]:
                        continue
                    try:
                        sr = client.get_cached(absolute)
                        script_count += 1
                        source_count += 1
                        local_candidates |= extract_candidates(absolute, sr.text, guard)
                    except Exception:
                        continue

                ordered = [u for u in sorted(local_candidates, key=priority) if u not in seen_endpoints]
                ordered = ordered[: max(1, min(args.max_endpoints_per_target, 12))]

                for url in ordered:
                    seen_endpoints.add(url)
                    try:
                        r = client.get(url)
                    except RuntimeError:
                        break
                    except Exception:
                        continue

                    obs = response_observation(url, r)
                    observations.append(obs)
                    ct = r.headers.get("content-type", "").lower()
                    path_low = urllib.parse.urlsplit(url).path.lower()
                    privateish = any(x in path_low for x in PRIVATE_HINTS)

                    if r.status_code in (401, 403):
                        findings.append(build_finding(
                            name, "js_endpoint_probe", url,
                            "Authentication boundary on first-party JS-discovered endpoint",
                            obs, confidence="info", reproducible=True, impact_evidence=False,
                        ))
                        continue

                    if r.status_code == 405 and r.headers.get("allow"):
                        findings.append(build_finding(
                            name, "js_endpoint_probe", url,
                            "Method boundary on first-party JS-discovered endpoint",
                            obs, confidence="info", reproducible=True, impact_evidence=False,
                        ))
                        continue

                    if r.status_code == 200 and "json" in ct:
                        keys = set()
                        try:
                            keys = json_key_names(r.json())
                        except Exception:
                            pass
                        account_keys = sorted(keys & ACCOUNT_KEYS)
                        if privateish and account_keys:
                            reproducible = False
                            second_status = None
                            second_keys = []
                            if budget.remaining > 0:
                                try:
                                    r2 = client.get(url)
                                    second_status = r2.status_code
                                    if "json" in r2.headers.get("content-type", "").lower():
                                        second_keys = sorted(json_key_names(r2.json()) & ACCOUNT_KEYS)
                                    reproducible = r2.status_code == 200 and second_keys == account_keys
                                except Exception:
                                    pass
                            findings.append(build_finding(
                                name, "js_endpoint_probe", url,
                                "Potential unauthenticated private API response discovered from first-party JavaScript",
                                {
                                    **obs,
                                    "private_path_hint": True,
                                    "account_shaped_key_names_only": account_keys,
                                    "second_status": second_status,
                                    "second_account_key_names_only": second_keys,
                                    "body_values_stored": False,
                                    "uat_requires_production_reproduction": True,
                                },
                                confidence="candidate", reproducible=reproducible, impact_evidence=False,
                            ))
                        else:
                            findings.append(build_finding(
                                name, "js_endpoint_probe", url,
                                "Public JSON endpoint discovered from first-party JavaScript",
                                {**obs, "json_key_count": len(keys), "body_values_stored": False},
                                confidence="info", reproducible=True, impact_evidence=False,
                            ))

            except Exception as exc:
                error = type(exc).__name__ + ":" + str(exc)[:160]

            actions.append({
                "program": name,
                "target": base,
                "module": "js_endpoint_probe",
                "requests_used": budget.used - before,
                "scope_blocks": budget.blocked,
                "request_errors": budget.errors,
                "first_party_scripts_fetched": script_count,
                "sources_parsed": source_count,
                "candidate_endpoints_discovered": len(local_candidates),
                "unique_endpoints_probed": sum(1 for x in observations if urllib.parse.urlsplit(x["url"]).hostname == urllib.parse.urlsplit(base).hostname),
                "error": error,
            })

    candidates = [x for x in findings if x.get("confidence") == "candidate"]
    summary = {
        "titan_version": TITAN_VERSION,
        "campaign": "syfe_uat_deep_js_endpoint_discovery",
        "production_automation": False,
        "uat_requires_production_reproduction": True,
        "findings_total": len(findings),
        "candidates": len(candidates),
        "reportable_confirmed": 0,
        "requests_used": sum(a["requests_used"] for a in actions),
        "scope_blocks": sum(a["scope_blocks"] for a in actions),
        "request_errors": sum(a["request_errors"] for a in actions),
        "status_counts": dict(Counter(str(x["status"]) for x in observations)),
        "findings": findings,
        "observations": observations,
        "actions": actions,
        "recommendation": "validate_only_if_candidate_then_manual_production_reproduction" if candidates else "authenticated_uat_testing_is_next_high_value_step",
    }

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(json.dumps({
        "campaign": summary["campaign"],
        "requests_used": summary["requests_used"],
        "scope_blocks": summary["scope_blocks"],
        "findings_total": summary["findings_total"],
        "candidates": summary["candidates"],
        "reportable_confirmed": 0,
        "recommendation": summary["recommendation"],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
