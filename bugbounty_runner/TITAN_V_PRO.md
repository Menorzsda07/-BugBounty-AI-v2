# TITAN V PRO 1.0

TITAN V PRO is the hardened evolution of the 12-runner bug bounty scanner. It is designed for explicitly authorized HackerOne assets and prioritizes scope control, low-impact testing, reproducibility, false-positive suppression, and per-action reporting.

## Core architecture

- `titan_v_pro_core.py`: ScopeGuard, request-budget/rate limiter, semantic response normalization, evidence redaction, stable fingerprints and priority scoring.
- `multi_scan.py`: 12-runner execution engine using the V PRO core for every request.
- `runner.py`: single-module compatibility runner using the same V PRO protections.
- `brain_code_vsystem.py`: Brain Code VSystem v3 with exact-fingerprint false-positive memory by default and observation history.
- `analyze.py`: campaign aggregation, Brain Code enrichment, ranking, campaign recommendation and per-action reports.
- `test_titan_v_pro.py`: offline regression tests.

## Mandatory safeguards

1. Every HTTP request must pass `ScopeGuard`.
2. Discovered third-party URLs may be recorded as observations but are never fetched unless explicitly allowlisted by the program config.
3. Excluded hosts override discovered URLs.
4. Request rate and per-target/per-runner budget are centrally enforced.
5. Redirects are never automatically followed.
6. V PRO safe configs reject non-empty `aggressive_modules`.
7. Response bodies, PII values, authentication material, banking data and secret values must not be retained as evidence.
8. Differential findings must be correlated with the controlled input change rather than hash variance alone.
9. A signal is not a confirmed vulnerability without impact evidence.

## False-positive model

Brain Code VSystem v3 supports two suppression scopes:

- `exact`: default for new validated false positives. Only the same program + host + bug class + signal fingerprint is suppressed.
- `class_host`: reserved for intentionally seeded legacy groups where an entire previously validated host/class pattern is known to be noise.

This prevents a benign signal from suppressing a future real vulnerability of the same class on another endpoint.

## Per-action report contract

Every module execution produces an action record containing:

- program
- target
- module / bug class searched
- requests used
- findings added
- ScopeGuard blocks
- execution error, if any
- duration

The analyzer emits:

- `combined.json`
- `action-report.json`
- `action-report.txt`
- `summary.txt` through the GitHub Actions workflow
- `brain-code-vsystem-snapshot.json`

## Campaign closeout fields

Every V PRO analysis contains:

- bugs/modules searched
- findings and suppressed false positives
- confirmed reportable vulnerabilities
- candidates still requiring validation
- missing work or action errors
- total requests and ScopeGuard blocks
- recommendation: continue targeted validation, prepare a report, finish lower-priority validation, or rotate to another authorized asset

## Current safe detector families

Surface/status, security headers, security.txt/robots, cookie hardening, JavaScript routes, API hints, source-map references, authorization-boundary candidates, method behavior, CORS, safe cache observation, open redirects, reflection/XSS context signals, SQL error differentials, malformed-input errors, error disclosures, OpenAPI/GraphQL exposure, signature-based sensitive files, DNS inventory, technology fingerprints, content-type anomalies, path normalization, encoding normalization, header behavior, method consistency, response-shape variance and cache metadata variance.

The V PRO safe profile intentionally avoids destructive state changes, privilege escalation, credential-required flows, denial-of-service behavior, persistent cache poisoning and collection of sensitive user data.
