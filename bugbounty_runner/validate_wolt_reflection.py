import html, json, re, time
import requests

BASE = "https://merchant.wolt.com/"
HEADER = {
    "X-HackerOne-Research": "ghosther",
    "User-Agent": "BugBounty-AI/V-PRO-1.0 scoped-security-research",
}
TESTS = [
    ("simple", "bbai_ctx_7391"),
    ("html_context", 'bbai_ctx_7391\"><svg data-h1="x">'),
]


def redact_snippet(s):
    s = re.sub(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '<EMAIL>', s)
    s = re.sub(r'\b\d{7,}\b', '<NUMBER>', s)
    return s[:500]


def contexts(text, marker):
    rows = []
    start = 0
    while len(rows) < 8:
        i = text.find(marker, start)
        if i < 0:
            break
        left = text[max(0, i - 180):i]
        right = text[i:i + 260]
        last_script_open = text.rfind('<script', 0, i)
        last_script_close = text.rfind('</script>', 0, i)
        in_script = last_script_open > last_script_close
        last_lt = text.rfind('<', 0, i)
        last_gt = text.rfind('>', 0, i)
        in_tag = last_lt > last_gt
        rows.append({
            "in_script": in_script,
            "in_tag": in_tag,
            "snippet": redact_snippet(left + right),
        })
        start = i + len(marker)
    return rows

results = []
for name, value in TESTS:
    r = requests.get(BASE, params={"q": value}, headers=HEADER, timeout=12, allow_redirects=False)
    text = r.text
    marker = "bbai_ctx_7391"
    rows = contexts(text, marker)
    results.append({
        "test": name,
        "status": r.status_code,
        "bytes": len(r.content),
        "marker_occurrences": text.count(marker),
        "raw_payload_reflected": value in text,
        "raw_svg_fragment_present": '<svg data-h1="x">' in text,
        "html_entity_escape_present": any(x in text for x in ("&lt;svg", "&quot;&gt;&lt;svg")),
        "unicode_escape_present": "\\u003csvg" in text.lower(),
        "contexts": rows,
    })
    time.sleep(1.5)

special = results[1]
if special["raw_svg_fragment_present"]:
    verdict = "html_injection_context_requires_minimal_xss_confirmation"
elif special["unicode_escape_present"] or special["html_entity_escape_present"]:
    verdict = "likely_safe_escaped_reflection"
else:
    verdict = "reflection_context_needs_review"

out = {
    "program": "wolt",
    "target": BASE,
    "candidate": "merchant reflected input / possible XSS",
    "requests_used": len(TESTS),
    "tests": results,
    "verdict": verdict,
    "javascript_executed": False,
    "reportable": False,
}
open("wolt-reflection-validation.json", "w", encoding="utf-8").write(json.dumps(out, indent=2, ensure_ascii=False))
print(json.dumps(out, indent=2, ensure_ascii=False))
