# ChatGPT Bug Bounty Continuity — Canonical Index

**Last consolidated:** 2026-08-15 (America/Sao_Paulo)  
**Canonical repository:** `Menorzsda07/-BugBounty-AI-v2`  
**Purpose:** allow a new ChatGPT/Codex session connected to this GitHub account to resume authorized bug-bounty work without rebuilding the history from zero.

> This is a sanitized continuity record. It intentionally contains no bearer tokens, cookies, refresh tokens, API keys, passwords, raw customer data, or other secrets.

## Mandatory startup sequence

A new agent should:

1. Read `AGENTS.md`.
2. Read this file.
3. Read the platform file for the requested workstream:
   - `docs/continuity/HACKERONE.md`
   - `docs/continuity/BUGCROWD.md`
4. Read `docs/continuity/state.json`.
5. Inspect the latest GitHub Actions run(s) referenced by that program before running anything new.
6. Re-check the live program scope/rules because scopes and bounty tables can change.

## Status legend

| Status | Meaning |
|---|---|
| `CONFIRMED_REPORT_READY` | Impact reproduced with report-quality evidence. Not necessarily submitted or accepted. |
| `CONFIRMED_SUBMITTED` | Submitted to the platform, awaiting or undergoing triage unless stated otherwise. |
| `ACCEPTED` | Explicitly accepted by program/triage. |
| `CANDIDATE` | Interesting behavior; impact not yet sufficiently proven. |
| `NEGATIVE` | Hypothesis tested and disproved / expected control worked. |
| `PLANNED` | Intended next test; not yet executed. |
| `UNKNOWN_REVIEW_REQUIRED` | Artifacts/workflows exist but the final result is not safely reconstructable from the recovered chat/evidence alone. |

## Current program dashboard

| Platform | Program/workstream | Current state | Confirmed report-ready findings | Current resume point |
|---|---|---|---:|---|
| HackerOne | GitLab | `CONFIRMED_REPORT_READY` | 1 | Submission package exists for MCP cross-origin URL confusion. Do not claim accepted until triage says so. |
| HackerOne | Coinbase / `coinbase/cb-mpc` | `CONFIRMED_REPORT_READY` | 1 | High-severity EdDSA-MP message/output aliasing PoC is reproducible through public API. Report package exists. |
| HackerOne | Syfe | `NEGATIVE` for recovered UAT campaign | 0 | UAT-only controlled testing produced no qualifying confirmed issue. Production automation remains prohibited. |
| HackerOne | Wolt | `UNKNOWN_REVIEW_REQUIRED` | 0 recovered | Phase 1/2 plus path/reflection validation were executed; inspect latest Actions logs before continuing. |
| Bugcrowd | Skyscanner | `NEGATIVE` through v36; next item `PLANNED` | 0 | Resume after v36. Next non-duplicative hypothesis recorded: anonymous refresh-token identity binding using only controlled identities. |
| Unclassified from recovered evidence | Klarna | `UNKNOWN_REVIEW_REQUIRED` | 0 recovered | Recon/source-map workflows exist; verify platform/scope and latest run before resuming. |
| Unclassified from recovered evidence | WisdomTree | `UNKNOWN_REVIEW_REQUIRED` | 0 recovered | Validation workflow/config exists; verify program/platform and latest result. |
| Unclassified from recovered evidence | Polygon | `UNKNOWN_REVIEW_REQUIRED` | 0 recovered | Validation workflow exists; verify program/platform and latest result. |
| Private TITAN inventory | Deribit / Dynatrace / Home Bargains | `UNKNOWN_REVIEW_REQUIRED` | 0 recovered here | Workflows exist in private `Bugbounty-titan-`; do not infer program/platform or findings without re-reading evidence. |

## Confirmed findings snapshot

### HackerOne — GitLab MCP origin confusion

**Status:** `CONFIRMED_REPORT_READY`  
**Suggested severity:** Low  
**Weakness:** CWE-346 — Origin Validation Error  
**Title:** `GitLab MCP add_branch ignores the supplied URL origin and mutates a same-path local project`

The shared GitLab MCP URL parser accepted arbitrary HTTP(S) origins, discarded the URL authority, and resolved only the path against the connected GitLab instance. A disposable GDK proof showed a URL whose host was `attacker.invalid` causing a branch to be created in a same-path local fixture repository using the connected user's existing permissions.

Important limitation: this is **not** an authentication or authorization bypass. Normal GitLab project permissions remain enforced; a same-path local resource and user/agent interaction are required.

Evidence pointers:

- tested GitLab source: `fc46f5b29edba351570261de5a3af45a66d3606a`
- TITAN branch: `titan/gitlab-mcp-url-origin-validation`
- TITAN validation commit: `c2d11ce5112f70dd43fd12a06d0526b50b81bad0`
- GDK workflow run: `31758045268`
- GDK job: `94638086675`
- sanitized artifact ID: `9204103684`
- artifact SHA-256: `c5fa9e6fe44efd7b73c38a1328df41ec66f701d0927b25acac4d06f0868818e1`
- earlier executor-level run: `31751151389`
- earlier executor proof commit: `193a06d221d7c01281735af4e75f62a95453e904`
- recovered proof file name: `GitLab_MCP_GDK_Proof.txt`
- recovered report package: `GitLab_HackerOne_Submission_MCP_Origin_Confusion.md`

Recovered bounty reference at report-preparation time: GitLab Low was recorded as approximately **USD 100–750**. This is only an estimate/reference until HackerOne/GitLab assigns the final priority and bounty.

### HackerOne — Coinbase `cb-mpc` EdDSA-MP aliasing

**Status:** `CONFIRMED_REPORT_READY`  
**Suggested severity:** High  
**Preferred weakness:** CWE-826, fallback CWE-416  
**Title:** `cb-mpc EdDSA-MP 2-of-3 message/output aliasing lets a malicious signer obtain an unauthorized Ed25519 signature`

The public `coinbase::api::eddsa_mp::sign_ac()` API calls `sig.free()` before the non-owning `mem_t msg` has been consumed and does not reject overlap between `msg` and `sig`. With the same short `buf_t` used for both, the output cleanup zeroizes the backing inline storage and changes the honest party's 32-byte non-zero signing input to 32 zero bytes.

The public-only 2-of-3 PoC demonstrated:

- 3 parties participated in DKG;
- policy was 2-of-3;
- honest P0 and malicious P1 were online, P2 offline;
- P0 approved a non-zero 32-byte message and aliased `msg`/`sig`;
- P1 was signature receiver and signed zero bytes;
- protocol succeeded and P1 received a valid Ed25519 signature for the zero message;
- the signature did not verify for P0's approved non-zero message;
- a distinct-output-buffer control was rejected.

Evidence pointers:

- upstream commit: `fdbb60346757271d5e0241f417e55dc8f289573c`
- PoC source commit: `4cbccf4c4eeeb842491e2fe3b6f1b5b522f9f7db`
- workflow run: `31840342298`
- job: `94895628825`
- key marker: `PUBLIC_ONLY_EDDSA_2OF3_UNAUTHORIZED_SIGNATURE_CONFIRMED=1`
- key marker: `V42_PUBLIC_ONLY_STANDALONE_CONFIRMED=1`
- recovered report package: `coinbase_cbmpc_REPORT_READY_FOR_HACKERONE.md`
- recovered evidence file: `coinbase_cbmpc_PROOF_EVIDENCE.txt`

Limitation: the deterministic short-buffer proof substitutes all-zero bytes of the same length. It does not prove arbitrary attacker-selected message substitution, private-key extraction, or RCE.

No trustworthy final bounty value was recovered for this finding. Keep severity/bounty separate: the report is High-suggested, but Coinbase/HackerOne decides final severity, validity, duplication, and payment.

## Skyscanner/Bugcrowd snapshot

Skyscanner has the largest current Bugcrowd workflow chain in this repository. It progressed from manual baseline/scope collection through Android static/dynamic surface mapping, OAuth/Partner Portal checks, account/Saved API authorization checks, capability-token checks, CORS, anonymous identity/token analysis, and controlled two-identity tests.

The current recovered state is **no confirmed vulnerability through v36**.

Important closed paths:

- **v35 — two controlled anonymous identities:** both identities received separate anonymous credentials/UTIDs; protected Saved, Price Alerts, and current-identity endpoints returned `401`. Authentication gates worked. `NEGATIVE`, bounty confirmed: **USD 0**.
- **v36 — `previous_utid` reclaim:** supplying a prior controlled UTID did not reclaim/reuse the previous identity; new identities/UTIDs were produced. `NEGATIVE`, bounty confirmed: **USD 0**.

Latest main commit at consolidation: `e38163b13751e40b3a1969f98f82da48a68b884f` (`test: check reclaim of own Skyscanner anonymous UTID v36`).

Next recorded, **not executed** hypothesis: test binding of an anonymous refresh token to its original controlled identity, using two identities owned by the researcher and without touching third-party data. See `docs/continuity/BUGCROWD.md` before executing.

Recovered Skyscanner reward table (2026-08-15 snapshot):

- P1: **USD 3,000–8,000**
- P2: **USD 900–3,000**
- P3: **USD 300–500**
- P4: **USD 100–150**

Treat this as a dated snapshot and re-check the program before relying on it.

## Syfe/HackerOne snapshot

Recovered controlled UAT campaign:

- UAT targets:
  - `uat-bugbounty.nonprod.syfe.com`
  - `api-uat-bugbounty.nonprod.syfe.com`
  - `alfred-uat-31.nonprod.syfe.com`
- automated requests were intentionally limited to UAT;
- production automation was explicitly excluded;
- UAT-only findings need production reproduction to be bounty-eligible under the recovered program constraints;
- only researcher-owned accounts are allowed;
- no data modification, privacy violations, DoS, social engineering, brute force, spam, or degradation;
- recovered earlier campaign count: 93 controlled requests across the three UAT targets;
- observed response set was primarily `401/403/404`, with no qualifying sensitive/admin/docs exposure recovered;
- arbitrary-origin CORS was not demonstrated;
- confirmed qualifying vulnerabilities recovered from that campaign: **0**.

Current config source: `bugbounty_runner/config.titan-syfe-uat.json`.

## Wolt/HackerOne snapshot

Recovered work performed:

- Phase 1: `wolt.com`, `restaurant-api.wolt.com`, `authentication.wolt.com` — 120 requests / 48 actions.
- Phase 2: `ops.wolt.com`, `merchant.wolt.com`, `drive.wolt.com`, `corporate.wolt.com` — 169 requests / 64 actions.
- Additional path validation: 6 requests.
- Merchant reflection validation: 2 requests.
- Recovered aggregate: **297 requests**, **34 ScopeGuard blocks**, **0 runner errors**.

Relevant files include:

- `.github/workflows/titan-wolt-phase1.yml`
- `.github/workflows/titan-wolt-phase2.yml`
- `.github/workflows/titan-wolt-path-validation.yml`
- `.github/workflows/titan-wolt-reflection-validation.yml`
- `bugbounty_runner/config.titan-wolt-phase1.json`
- `bugbounty_runner/config.titan-wolt-phase2.json`
- `bugbounty_runner/validate_wolt_merchant_path.py`
- `bugbounty_runner/validate_wolt_path_norm.py`
- `bugbounty_runner/validate_wolt_reflection.py`

The exact final vulnerability verdict was not recovered with enough confidence from the available chat snapshot. Therefore the workstream is deliberately `UNKNOWN_REVIEW_REQUIRED`; inspect the latest Actions logs before any new testing and do not assume a bug exists.

## Repository inventory relevant to continuity

### Public canonical repository: `Menorzsda07/-BugBounty-AI-v2`

Major families currently present:

- Skyscanner Bugcrowd workflows v1–v36.
- Coinbase `cb-mpc` audit workflows and public PoCs, including extensive aliasing, access-policy, replay, refresh, malformed-transport, DKG and sanitizer probes.
- Syfe low-impact/UAT workflows and TITAN configs.
- Wolt phase/path/reflection workflows and configs.
- Klarna playground/bundle recon workflows.
- WisdomTree validation workflow/config.
- Polygon validation workflow.
- TITAN V PRO runner/core/memory/scope-guard infrastructure.

### Private evidence repository: `Menorzsda07/Bugbounty-titan-`

Recovered main-branch families:

- Deribit
- Dynatrace
- Home Bargains
- private TITAN runner/configs

Recovered GitLab-specific branch:

- `titan/gitlab-mcp-url-origin-validation`
- contains `gitlab-mcp-url-origin-validation.yml` and `gitlab-mcp-gdk-validation.yml`

Do not infer the platform, scope, final finding status, or bounty of Deribit/Dynatrace/Home Bargains merely from workflow names. Re-read their program rules and Actions evidence first.

## Continuity rules for future discoveries

When a new finding is discovered, immediately add a compact record to the correct platform document with:

- exact program and asset;
- date;
- tested version/commit;
- hypothesis;
- safe reproduction boundary;
- result and status label;
- impact and limitations;
- workflow/run/job/artifact identifiers;
- report/submission/triage status;
- bounty estimate and source/date when applicable;
- next step.

If triage responds, update the status instead of creating a disconnected new note. A future agent should be able to tell from this repository whether an item is merely interesting, disproved, report-ready, submitted, accepted, duplicate, or closed.
