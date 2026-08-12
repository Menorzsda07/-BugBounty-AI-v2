import argparse, json, os, urllib.parse
from collections import Counter

from multi_scan import ScopedClient, json_key_names
from titan_v_pro_core import RequestBudget, ScopeGuard, TITAN_VERSION, build_finding, validate_config

AUTH_PATHS = (
    "/login",
    "/signin",
    "/auth/login",
    "/api/auth/login",
    "/api/me",
    "/api/user",
    "/api/account",
    "/api/v1/me",
    "/api/v1/user",
    "/api/v1/account",
    "/.well-known/openid-configuration",
    "/oauth/authorize",
)
PRIVATE_HINTS = ("/me", "/user", "/account", "/admin", "/portfolio", "/wallet", "/balance")
ACCOUNT_KEYS = {
    "email", "user_id", "userid", "account_id", "accountid", "customer_id",
    "portfolio", "portfolio_id", "balance", "balances", "holdings", "orders",
    "transactions", "kyc", "phone", "address", "name",
}


def safe_location(value):
    if not value:
        return None
    try:
        p = urllib.parse.urlsplit(value)
        return {
            "scheme": p.scheme,
            "host": p.hostname,
            "path": p.path or "/",
            "query_stored": False,
        }
    except Exception:
        return {"present": True, "query_stored": False}


def load_cfg(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    cfg = load_cfg(args.config)
    errors = validate_config(cfg)
    if errors:
        raise SystemExit("invalid TITAN config: " + "; ".join(errors))

    findings, observations, actions = [], [], []

    for prog in cfg.get("programs", []):
        name = prog.get("name", "unknown")
        guard = ScopeGuard(prog)
        for base in prog.get("targets", []):
            budget = RequestBudget(
                int(cfg.get("max_requests_per_target_per_runner", 20)),
                int(cfg.get("delay_ms", 1200)),
            )
            client = ScopedClient(guard, budget)
            error = None

            try:
                targets = [base]
                for path in AUTH_PATHS:
                    u = guard.safe_join(base, path)
                    if u and u not in targets:
                        targets.append(u)

                for url in targets:
                    if budget.remaining <= 0:
                        break
                    try:
                        r = client.get(url)
                    except Exception:
                        continue

                    ct = r.headers.get("content-type", "")
                    keys = set()
                    if "json" in ct.lower():
                        try:
                            keys = json_key_names(r.json())
                        except Exception:
                            pass
                    account_keys = sorted(keys & ACCOUNT_KEYS)
                    path_low = urllib.parse.urlsplit(url).path.lower()
                    privateish = any(x in path_low for x in PRIVATE_HINTS)

                    obs = {
                        "url": url,
                        "status": r.status_code,
                        "ctype": ct,
                        "bytes": len(r.content),
                        "redirect": safe_location(r.headers.get("location", "")),
                        "json_key_names_only": sorted(keys)[:80],
                        "body_values_stored": False,
                    }
                    observations.append(obs)

                    if r.status_code == 200 and privateish and account_keys:
                        findings.append(build_finding(
                            name,
                            "auth_surface_map",
                            url,
                            "Potential unauthenticated private API response on curated auth boundary path",
                            {
                                "status": 200,
                                "ctype": ct,
                                "account_shaped_key_names_only": account_keys,
                                "body_values_stored": False,
                                "uat_requires_production_reproduction": True,
                            },
                            confidence="candidate",
                            reproducible=False,
                            impact_evidence=False,
                        ))
                    elif r.status_code in (401, 403):
                        findings.append(build_finding(
                            name,
                            "auth_surface_map",
                            url,
                            "Authentication boundary observed",
                            {"status": r.status_code, "ctype": ct},
                            confidence="info",
                            reproducible=True,
                            impact_evidence=False,
                        ))
                    elif r.status_code in (301, 302, 303, 307, 308) and r.headers.get("location"):
                        findings.append(build_finding(
                            name,
                            "auth_surface_map",
                            url,
                            "Authentication or routing redirect observed",
                            {"status": r.status_code, "redirect": safe_location(r.headers.get("location", ""))},
                            confidence="info",
                            reproducible=True,
                            impact_evidence=False,
                        ))

            except Exception as exc:
                error = type(exc).__name__ + ":" + str(exc)[:160]

            actions.append({
                "program": name,
                "target": base,
                "module": "auth_surface_map",
                "requests_used": budget.used,
                "scope_blocks": budget.blocked,
                "request_errors": budget.errors,
                "error": error,
            })

    candidates = [x for x in findings if x.get("confidence") == "candidate"]
    payload = {
        "titan_version": TITAN_VERSION,
        "campaign": "syfe_uat_curated_auth_surface_map",
        "production_automation": False,
        "uat_requires_production_reproduction": True,
        "findings_total": len(findings),
        "candidates": len(candidates),
        "reportable_confirmed": 0,
        "requests_used": sum(x["requests_used"] for x in actions),
        "scope_blocks": sum(x["scope_blocks"] for x in actions),
        "request_errors": sum(x["request_errors"] for x in actions),
        "status_counts": dict(Counter(str(x["status"]) for x in observations)),
        "findings": findings,
        "observations": observations,
        "actions": actions,
        "recommendation": "validate_candidate_safely" if candidates else "test_credentials_required_for_next_high_value_phase",
    }

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    print(json.dumps({
        "campaign": payload["campaign"],
        "requests_used": payload["requests_used"],
        "scope_blocks": payload["scope_blocks"],
        "request_errors": payload["request_errors"],
        "status_counts": payload["status_counts"],
        "candidates": payload["candidates"],
        "reportable_confirmed": 0,
        "recommendation": payload["recommendation"],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
