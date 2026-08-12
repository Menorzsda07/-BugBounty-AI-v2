import hashlib, json, re, time, urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

TITAN_VERSION = "V PRO 1.0"

VOLATILE_PATTERNS = [
    (re.compile(r'(?i)(csrfmiddlewaretoken["\'\s:=]+)[A-Za-z0-9_-]{16,}'), r'\1<VOLATILE>'),
    (re.compile(r'(?i)(nonce=["\'])[A-Za-z0-9_+/=-]{8,}(["\'])'), r'\1<VOLATILE>\2'),
    (re.compile(r'(?i)(ray id:?[\s<]*)([0-9a-f]{12,})'), r'\1<VOLATILE>'),
    (re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b'), '<UUID>'),
    (re.compile(r'\b20\d\d-[01]\d-[0-3]\d[T ][0-2]\d:[0-5]\d:[0-5]\d(?:\.\d+)?Z?\b'), '<TIMESTAMP>'),
    (re.compile(r'(?i)(applicationTime\s*[:=]\s*)\d+'), r'\1<VOLATILE>'),
    (re.compile(r'(?i)(queueTime\s*[:=]\s*)\d+'), r'\1<VOLATILE>'),
]

SENSITIVE_KEY_RE = re.compile(
    r'(?i)(authorization|cookie|set-cookie|password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|session)'
)

MODULE_FAMILIES = {
    "auth_boundary": "authz-bypass",
    "xss_reflection": "xss",
    "sqli_differential": "sqli",
    "cors": "cors",
    "cache": "cache-confusion",
    "cache_variance": "cache-confusion",
    "path_normalization_diff": "path-traversal",
    "encoding_diff": "input-normalization",
    "redirects": "open-redirect",
    "sensitive_files": "sensitive-exposure",
    "error_diff": "error-handling",
}

PRIORITY_BY_MODULE = {
    "auth_boundary": 18,
    "sqli_differential": 18,
    "cors": 16,
    "cache": 15,
    "sensitive_files": 15,
    "xss_reflection": 14,
    "redirects": 12,
    "error_diff": 10,
    "path_normalization_diff": 9,
    "encoding_diff": 8,
    "method_consistency": 7,
    "header_behavior_diff": 6,
    "response_shape_diff": 6,
    "cache_variance": 6,
    "headers": 2,
    "dns_http_inventory": 1,
    "fingerprints": 1,
}


def normalize_text(text: str) -> str:
    out = text or ""
    for rx, repl in VOLATILE_PATTERNS:
        out = rx.sub(repl, out)
    return out


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes((text or "").encode("utf-8", "replace"))


def semantic_tokens(text: str) -> Set[str]:
    toks = re.findall(r'[a-z][a-z0-9_./:-]{2,}', normalize_text(text).lower())
    if len(toks) < 3:
        return set(toks)
    return {' '.join(toks[i:i + 3]) for i in range(len(toks) - 2)}


def jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / max(1, len(a | b))


def semantic_similarity(a: str, b: str) -> float:
    return jaccard(semantic_tokens(a), semantic_tokens(b))


def response_structure(text: str) -> Dict[str, Any]:
    s = text or ""
    title = re.search(r'<title[^>]*>(.*?)</title>', s, re.I | re.S)
    return {
        "title": re.sub(r'\s+', ' ', title.group(1)).strip() if title else "",
        "tags": {t: len(re.findall(fr'<{t}\b', s, re.I)) for t in ("html", "body", "div", "script", "link", "form", "input")},
        "has_json_shape": bool(re.match(r'^\s*[\[{]', s)),
    }


def response_meta(resp: Any) -> Dict[str, Any]:
    text = getattr(resp, "text", "") or ""
    content = getattr(resp, "content", b"") or b""
    headers = getattr(resp, "headers", {}) or {}
    norm = normalize_text(text)
    return {
        "status": getattr(resp, "status_code", None),
        "bytes": len(content),
        "ctype": headers.get("content-type", ""),
        "location": headers.get("location", ""),
        "server": headers.get("server", ""),
        "cache_control": headers.get("cache-control", ""),
        "etag": headers.get("etag", ""),
        "raw_sha256": sha256_bytes(content),
        "normalized_sha256": sha256_text(norm),
        "structure": response_structure(text),
    }


def materially_equivalent(a: Any, b: Any, threshold: float = 0.999) -> Tuple[bool, Dict[str, Any]]:
    ma, mb = response_meta(a), response_meta(b)
    sim = semantic_similarity(getattr(a, "text", ""), getattr(b, "text", ""))
    equal = (
        ma["status"] == mb["status"]
        and ma["ctype"] == mb["ctype"]
        and ma["structure"] == mb["structure"]
        and sim >= threshold
    )
    return equal, {"semantic_similarity": sim, "a": ma, "b": mb}


def redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            out[k] = "<REDACTED>" if SENSITIVE_KEY_RE.search(str(k)) else redact_value(v)
        return out
    if isinstance(value, list):
        return [redact_value(x) for x in value]
    if isinstance(value, tuple):
        return [redact_value(x) for x in value]
    if isinstance(value, str):
        if len(value) > 600:
            return value[:600] + "…"
        return value
    return value


def stable_fingerprint(program: str, host: str, module: str, title: str, target: str) -> str:
    raw = f"{program}|{host}|{module}|{title}|{target}".lower().strip()
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def score_finding(finding: Dict[str, Any]) -> int:
    score = PRIORITY_BY_MODULE.get(finding.get("module", ""), 5)
    confidence = finding.get("confidence", "candidate")
    score += {"validated": 35, "candidate": 15, "info": 0}.get(confidence, 5)
    if finding.get("reproducible"):
        score += 20
    if finding.get("impact_evidence"):
        score += 25
    if finding.get("brain_status") == "known_false_positive":
        score -= 100
    return max(0, min(100, score))


@dataclass
class ScopeGuard:
    program: Dict[str, Any]
    target_rules: Dict[Tuple[str, str, int], List[str]] = field(default_factory=dict)
    excluded_hosts: Set[str] = field(default_factory=set)

    def __post_init__(self):
        self.excluded_hosts = {str(x).lower().strip(".") for x in self.program.get("excluded_hosts", []) if x}
        for target in self.program.get("targets", []):
            u = urllib.parse.urlsplit(target)
            if u.scheme not in ("http", "https") or not u.hostname:
                continue
            port = u.port or (443 if u.scheme == "https" else 80)
            key = (u.scheme.lower(), u.hostname.lower(), port)
            path = u.path or "/"
            if not path.startswith("/"):
                path = "/" + path
            self.target_rules.setdefault(key, []).append(path)

    def _host_excluded(self, host: str) -> bool:
        host = (host or "").lower().strip(".")
        return any(host == ex or host.endswith("." + ex) for ex in self.excluded_hosts)

    def check(self, url: str) -> Tuple[bool, str]:
        try:
            u = urllib.parse.urlsplit(url)
            if u.scheme not in ("http", "https") or not u.hostname:
                return False, "invalid_or_unsupported_url"
            host = u.hostname.lower()
            if self._host_excluded(host):
                return False, "excluded_host"
            port = u.port or (443 if u.scheme == "https" else 80)
            key = (u.scheme.lower(), host, port)
            paths = self.target_rules.get(key, [])
            if not paths:
                return False, "host_or_scheme_not_allowlisted"
            req_path = u.path or "/"
            if "/" in paths:
                return True, "exact_host_allowlist"
            for allowed in paths:
                prefix = allowed if allowed.endswith("/") else allowed + "/"
                if req_path == allowed or req_path.startswith(prefix):
                    return True, "path_prefix_allowlist"
            return False, "path_outside_allowlist"
        except Exception:
            return False, "scope_parse_error"

    def assert_url(self, url: str) -> None:
        ok, reason = self.check(url)
        if not ok:
            raise ValueError(f"ScopeGuard blocked {url}: {reason}")

    def safe_join(self, base: str, ref: str) -> Optional[str]:
        url = urllib.parse.urljoin(base, ref)
        ok, _ = self.check(url)
        return url if ok else None


@dataclass
class RequestBudget:
    max_requests: int
    delay_ms: int = 1000
    remaining: int = field(init=False)
    used: int = 0
    blocked: int = 0
    errors: int = 0
    last_request_at: float = 0.0

    def __post_init__(self):
        self.remaining = int(self.max_requests)
        self.delay_ms = max(0, int(self.delay_ms))

    def consume(self) -> None:
        if self.remaining <= 0:
            raise RuntimeError("request_budget_exhausted")
        now = time.time()
        minimum_gap = self.delay_ms / 1000.0
        wait = minimum_gap - (now - self.last_request_at)
        if self.last_request_at and wait > 0:
            time.sleep(wait)
        self.remaining -= 1
        self.used += 1
        self.last_request_at = time.time()


@dataclass
class ActionTrace:
    program: str
    target: str
    module: str
    started_at: float = field(default_factory=time.time)
    requests_before: int = 0
    requests_after: int = 0
    findings_before: int = 0
    findings_after: int = 0
    blocked_urls: int = 0
    error: Optional[str] = None

    def finish(self, budget: RequestBudget, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        self.requests_after = budget.used
        self.findings_after = len(findings)
        return {
            "program": self.program,
            "target": self.target,
            "module": self.module,
            "requests_used": max(0, self.requests_after - self.requests_before),
            "findings_added": max(0, self.findings_after - self.findings_before),
            "blocked_urls": self.blocked_urls,
            "error": self.error,
            "duration_ms": round((time.time() - self.started_at) * 1000, 1),
        }


def build_finding(program: str, module: str, target: str, title: str, evidence: Any,
                  confidence: str = "candidate", reproducible: bool = False,
                  impact_evidence: bool = False) -> Dict[str, Any]:
    host = urllib.parse.urlsplit(target).hostname or "unknown"
    item = {
        "program": program,
        "module": module,
        "target": target,
        "title": title,
        "evidence": redact_value(evidence),
        "confidence": confidence,
        "reproducible": bool(reproducible),
        "impact_evidence": bool(impact_evidence),
        "titan_version": TITAN_VERSION,
        "family_hint": MODULE_FAMILIES.get(module),
    }
    item["fingerprint"] = stable_fingerprint(program, host, module, title, target)
    item["priority_score"] = score_finding(item)
    return item


def validate_config(cfg: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    programs = cfg.get("programs")
    if not isinstance(programs, list) or not programs:
        errors.append("config.programs must be a non-empty list")
        return errors
    seen = set()
    for p in programs:
        name = str(p.get("name", "")).strip()
        if not name:
            errors.append("program missing name")
        if name in seen:
            errors.append(f"duplicate program name: {name}")
        seen.add(name)
        targets = p.get("targets", [])
        if not isinstance(targets, list) or not targets:
            errors.append(f"program {name or '<unknown>'} has no targets")
        guard = ScopeGuard(p)
        for t in targets:
            ok, reason = guard.check(t)
            if not ok:
                errors.append(f"program {name}: target rejected by own scope guard: {t} ({reason})")
    if int(cfg.get("max_requests_per_target_per_runner", 30)) > 60:
        errors.append("max_requests_per_target_per_runner exceeds V PRO safety cap (60)")
    if int(cfg.get("delay_ms", 1000)) < 500:
        errors.append("delay_ms below V PRO safety floor (500ms)")
    if cfg.get("aggressive_modules"):
        errors.append("aggressive_modules must remain empty in V PRO safe profile")
    return errors


def dump_json(path: str, payload: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
