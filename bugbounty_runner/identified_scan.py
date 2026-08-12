import argparse, json, sys

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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--runner", type=int, required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    required_headers = load_request_headers(args.config)
    original = multi_scan.requests.request

    def identified_request(method, url, headers=None, **kwargs):
        merged = dict(required_headers)
        merged.update(dict(headers or {}))
        return original(method, url, headers=merged, **kwargs)

    multi_scan.requests.request = identified_request
    sys.argv = ["multi_scan.py", "--config", args.config, "--runner", str(args.runner), "--out", args.out]
    multi_scan.main()


if __name__ == "__main__":
    main()
