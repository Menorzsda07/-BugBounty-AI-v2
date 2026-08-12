import argparse, json, sys, urllib.parse

import multi_scan


def load_request_headers(config_path):
    cfg = json.load(open(config_path, encoding="utf-8"))
    headers = cfg.get("request_headers", {}) or {}
    if not isinstance(headers, dict):
        raise SystemExit("request_headers must be an object")
    clean = {}
    forbidden = {"authorization", "cookie", "set-cookie", "proxy-authorization"}
    for k, v in headers.items():
        name = str(k).strip()
        value = str(v).strip()
        if not name or not value:
            continue
        if name.lower() in forbidden:
            raise SystemExit(f"refusing secret/auth header in public config: {name}")
        clean[name] = value
    return clean


def benign_path_canonicalization(finding):
    if finding.get("module") != "path_normalization_diff":
        return False
    variants = (finding.get("evidence") or {}).get("variants") or []
    if len(variants) != 3:
        return False
    base, doubled, dotted = variants
    target = urllib.parse.urlsplit(finding.get("target", ""))
    raw = target.path or "/"
    acceptable_locations = {raw, raw.rstrip("/") + "/", raw.rstrip("/") or "/"}
    redirect_ok = (
        doubled.get("status") in (301, 302, 307, 308)
        and doubled.get("location") in acceptable_locations
    )
    same_route_shape = (
        base.get("status") == dotted.get("status")
        and base.get("ctype") == dotted.get("ctype")
        and base.get("bytes") == dotted.get("bytes")
        and base.get("structure") == dotted.get("structure")
    )
    return bool(redirect_ok and same_route_shape)


def demote_unvalidated_xss(finding):
    if finding.get("module") != "xss_reflection":
        return False
    evidence = finding.get("evidence") or {}
    if not evidence.get("marker_reflected"):
        return False
    if not evidence.get("special_char_execution_not_tested"):
        return False
    finding["confidence"] = "info"
    finding["impact_evidence"] = False
    finding["identified_scan_note"] = "alphanumeric_reflection_only_requires_context_validation"
    return True


def postprocess_output(out_path):
    data = json.load(open(out_path, encoding="utf-8"))
    findings = data.get("findings", []) or []
    kept, suppressed, demoted = [], [], []
    for finding in findings:
        if benign_path_canonicalization(finding):
            suppressed.append({
                "module": finding.get("module"),
                "target": finding.get("target"),
                "title": finding.get("title"),
                "reason": "benign_path_canonicalization",
            })
            continue
        if demote_unvalidated_xss(finding):
            demoted.append({
                "module": finding.get("module"),
                "target": finding.get("target"),
                "reason": "alphanumeric_reflection_without_special_character_validation",
            })
        kept.append(finding)

    data["findings"] = kept
    if suppressed:
        data["suppressed_by_identified_scan"] = suppressed
    if demoted:
        data["demoted_by_identified_scan"] = demoted
    if suppressed or demoted:
        stats = data.setdefault("stats", {})
        stats["findings"] = len(kept)
        stats["suppressed_benign_canonicalization"] = len(suppressed)
        stats["demoted_unvalidated_xss"] = len(demoted)
        open(out_path, "w", encoding="utf-8").write(json.dumps(data, indent=2, ensure_ascii=False))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--runner", type=int, required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    required_headers = load_request_headers(args.config)
    original = multi_scan.requests.request

    def identified_request(method, url, headers=None, **kwargs):
        merged = dict(headers or {})
        merged.update(required_headers)
        return original(method, url, headers=merged, **kwargs)

    multi_scan.requests.request = identified_request
    sys.argv = ["multi_scan.py", "--config", args.config, "--runner", str(args.runner), "--out", args.out]
    multi_scan.main()
    postprocess_output(args.out)


if __name__ == "__main__":
    main()
