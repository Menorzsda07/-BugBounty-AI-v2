import json, time
import requests

HEADER = {"X-HackerOne-Research": "ghosther", "User-Agent": "BugBounty-AI/V-PRO-1.0 scoped-security-research"}
URLS = [
    "https://wolt.com/",
    "https://wolt.com//",
    "https://wolt.com/./",
]

def meta(r):
    return {
        "status": r.status_code,
        "location": r.headers.get("location", ""),
        "content_type": r.headers.get("content-type", ""),
        "bytes": len(r.content),
        "cache_control": r.headers.get("cache-control", ""),
    }

rows = []
for round_no in (1, 2):
    for url in URLS:
        r = requests.get(url, headers=HEADER, timeout=12, allow_redirects=False)
        rows.append({"round": round_no, "url": url, **meta(r)})
        time.sleep(1.5)

by_url = {u: [x for x in rows if x["url"] == u] for u in URLS}
canonical = by_url["https://wolt.com/"]
double = by_url["https://wolt.com//"]
dot = by_url["https://wolt.com/./"]

benign = (
    all(x["status"] == 200 for x in canonical)
    and all(x["status"] in (301, 302, 307, 308) and x["location"] == "/" for x in double)
    and all(x["status"] == 200 for x in dot)
    and all(x["bytes"] == canonical[0]["bytes"] for x in canonical + dot)
)

result = {
    "program": "wolt",
    "candidate": "path_normalization_diff root canonicalization",
    "requests_used": len(rows),
    "rows": rows,
    "verdict": "false_positive_benign_canonicalization" if benign else "needs_further_review",
    "impact_evidence": False,
    "reportable": False,
}
open("wolt-path-validation.json", "w", encoding="utf-8").write(json.dumps(result, indent=2))
print(json.dumps(result, indent=2))
