# HackerOne Continuity Record

**Last consolidated:** 2026-08-15  
**Rule:** this file contains HackerOne workstreams only. Do not import Bugcrowd scope, headers, bounty tables, evidence, or conclusions into these programs.

## 1. GitLab — MCP absolute-URL origin confusion

### State

- **Status:** `CONFIRMED_REPORT_READY`
- **Program:** GitLab / HackerOne
- **Asset:** GitLab source code, `https://gitlab.com/gitlab-org/gitlab`
- **Affected component:** GitLab MCP server
- **Suggested weakness:** CWE-346 — Origin Validation Error
- **Suggested severity:** Low
- **Prepared title:** `GitLab MCP add_branch ignores the supplied URL origin and mutates a same-path local project`
- **Test date:** 2026-08-14

### Root cause

The shared MCP URL parser accepts any syntactically valid HTTP(S) URL but does not compare its normalized origin with the GitLab instance serving the authenticated MCP request. The helper then extracts only `URI#path`, discarding the authority before local resource lookup.

Therefore a foreign URL shaped like:

```text
https://attacker.invalid/victim/project
```

can be interpreted as local project path `victim/project` on the connected GitLab instance.

### Demonstrated impact

A disposable GitLab Development Kit environment used the real GitLab schema, test database, repository fixture and Gitaly. The focused proof verified:

- the supplied host was `attacker.invalid`;
- the proof branch did not exist before execution;
- `add_branch` returned success;
- the branch existed in the same-path local fixture repository after execution;
- the GitLab schema was not replaced with a mutation recorder/stub.

Observed decisive marker:

```text
TITAN_GDK_CONFIRMED external_host=attacker.invalid local_branch_created=true schema_stubbed=false
1 example, 0 failures
```

Supporting executor-level evidence also traced the same authority loss into local write dispatch for:

- `add_branch` -> `createBranch`
- `create_workitem_note` -> `createNote`

The fixture-backed final mutation proof is for `add_branch`; `create_workitem_note` is supporting schema/executor-boundary evidence.

### Limitations / do not overclaim

- No authentication bypass.
- No authorization bypass.
- Existing GitLab permissions remain enforced.
- A same-path local project/resource is required.
- User/agent interaction is required to pass the external URL to the MCP tool.
- Do not claim account takeover, secret disclosure, arbitrary privilege escalation, or impact beyond existing permissions.

### Evidence identifiers

- Tested GitLab source commit: `fc46f5b29edba351570261de5a3af45a66d3606a`
- Public mirror freshness check at preparation time: `cb59fb1118c59ee726afa759c7f49a5d8c7ee8d9`
- Private evidence repo: `Menorzsda07/Bugbounty-titan-`
- Evidence branch: `titan/gitlab-mcp-url-origin-validation`
- TITAN validation commit: `c2d11ce5112f70dd43fd12a06d0526b50b81bad0`
- GDK workflow: `.github/workflows/gitlab-mcp-gdk-validation.yml`
- GDK run: `31758045268`
- GDK job: `94638086675`
- Sanitized artifact ID: `9204103684`
- Sanitized artifact filename: `GitLab_HackerOne_GDK_Evidence.zip`
- Artifact SHA-256: `c5fa9e6fe44efd7b73c38a1328df41ec66f701d0927b25acac4d06f0868818e1`
- Earlier executor-level run: `31751151389`
- Earlier executor-proof commit: `193a06d221d7c01281735af4e75f62a95453e904`
- Recovered proof: `GitLab_MCP_GDK_Proof.txt`
- Recovered prepared submission: `GitLab_HackerOne_Submission_MCP_Origin_Confusion.md`

### Testing safety already observed

- No production GitLab service tested.
- No personal GitLab token/credential used in the GDK proof.
- No automated vulnerability scanner used.
- Only one proof branch was created in a disposable local fixture.
- GDK container/database/repository/branch were destroyed during cleanup.
- No remote project, branch, note, account, user data or third-party service was modified.

### Bounty snapshot

At report preparation time, the public GitLab Low reference was recorded as **USD 100–750**. This is a dated estimate only. Final validity, severity, duplication and bounty are controlled by GitLab/HackerOne.

### Resume point

The technical proof is sufficiently strong for submission. Before doing more technical testing, first check whether the report has already been submitted from another session and whether triage has responded. If not submitted, use the prepared report and sanitized proof attachment. Do not re-run production testing to strengthen an already fixture-confirmed issue.

---

## 2. Coinbase — `coinbase/cb-mpc` EdDSA-MP message/output aliasing

### State

- **Status:** `CONFIRMED_REPORT_READY`
- **Program:** Coinbase / HackerOne
- **Asset:** `coinbase/cb-mpc`
- **Suggested severity:** High
- **Preferred weakness:** CWE-826 — Premature Release of Resource During Expected Lifetime
- **Fallback weakness:** CWE-416 — Use After Free
- **Prepared title:** `cb-mpc EdDSA-MP 2-of-3 message/output aliasing lets a malicious signer obtain an unauthorized Ed25519 signature`

### Root cause

The public API:

```cpp
coinbase::api::eddsa_mp::sign_ac(..., mem_t msg, ..., buf_t& sig)
```

clears/releases `sig` before `msg` is consumed. `mem_t` is a non-owning view, and the API does not reject input/output overlap. When a short `buf_t` is passed as both `msg` and `sig`, the implicit `mem_t` view is created first; `sig.free()` then securely zeroizes the same inline backing storage while `msg` still references it.

For the tested 32-byte input, the honest party's non-zero message deterministically becomes 32 zero bytes.

### Demonstrated impact

Public API only, real 2-of-3 threshold scenario:

1. All three parties participate in DKG.
2. Access policy is 2-of-3.
3. At signing time honest P0 and malicious P1 are online; P2 is offline.
4. Honest P0 approves a non-zero 32-byte message.
5. P0 passes the same `buf_t` as both message input and signature output.
6. Malicious P1 uses 32 zero bytes and is the signature receiver.
7. Signing succeeds.
8. P1 receives a valid Ed25519 signature for the zero message.
9. Independent OpenSSL verification succeeds for the zero message.
10. The same signature fails verification for P0's originally approved non-zero message.
11. A control run using a distinct output buffer is rejected and the malicious participant receives no signature.

Decisive markers:

```text
PUBLIC_ONLY_EDDSA_2OF3_ALIAS_POC ... exploit_success=1 attacker_received=1 verifies_attacker_zero=1 verifies_honest_approved=0 control_rejected=1
PUBLIC_ONLY_EDDSA_2OF3_UNAUTHORIZED_SIGNATURE_CONFIRMED=1
V42_PUBLIC_ONLY_STANDALONE_CONFIRMED=1
```

### Evidence identifiers

- Exact tested upstream commit: `fdbb60346757271d5e0241f417e55dc8f289573c`
- Public-only PoC source commit: `4cbccf4c4eeeb842491e2fe3b6f1b5b522f9f7db`
- GitHub Actions run: `31840342298`
- Job: `94895628825`
- Job name: `public-only-poc`
- Runner: Ubuntu 24.04
- Recovered report: `coinbase_cbmpc_REPORT_READY_FOR_HACKERONE.md`
- Recovered proof/evidence: `coinbase_cbmpc_PROOF_EVIDENCE.txt`
- Related repository PoCs/workflows are under `pocs/` and `.github/workflows/cbmpc-*`.

The public-only build explicitly checks that the PoC does not rely on installed internal headers, and signature verification is independent through OpenSSL Ed25519 APIs.

### Limitations / do not overclaim

- The short-buffer manifestation changes the message to all-zero bytes of the same length.
- It does not demonstrate arbitrary attacker-chosen message substitution.
- It does not demonstrate private-key extraction.
- It does not demonstrate remote code execution.
- Severity is suggested High, not program-confirmed.

### Later cb-mpc research inventory

After the report-quality v42 proof, the repository contains many further probes covering areas such as:

- access-policy substitution/relabeling;
- peer-name binding/misbinding;
- PVE quorum behavior;
- malformed transport and sanitizer checks;
- refresh invariants and malicious participants;
- cross-session signing and DKG replay;
- ECDSA2P, EdDSA2P and ECDSA-MP variants;
- DKG sanitizer/diagnostic paths.

Do **not** treat the existence of a later workflow/PoC as another confirmed vulnerability. The only report-ready Coinbase issue recovered with clear proof is the EdDSA-MP aliasing issue above. Re-read the specific Actions log before promoting any later experiment.

### Bounty

No reliable Coinbase bounty amount for this exact finding was recovered into the continuity record. Do not invent one. Re-check the current Coinbase HackerOne bounty table at submission/triage time.

### Resume point

Before further technical work, check whether this prepared report has already been submitted in another session and whether Coinbase/HackerOne has responded. If not, the report/evidence package is ready. For new research, use later cb-mpc workflows as hypothesis history to avoid repeating already explored families.

---

## 3. Syfe — UAT-only automated campaign

### State

- **Status:** `NEGATIVE` for the recovered UAT campaign
- **Confirmed qualifying vulnerabilities recovered:** 0
- **Current authoritative local config:** `bugbounty_runner/config.titan-syfe-uat.json`

### Recovered UAT targets

- `https://uat-bugbounty.nonprod.syfe.com`
- `https://api-uat-bugbounty.nonprod.syfe.com`
- `https://alfred-uat-31.nonprod.syfe.com`

### Explicitly excluded from automated requests in the recovered config

- `www.syfe.com`
- `api.syfe.com`
- `alfred.syfe.com`
- `mark8.syfe.com`
- `help.syfe.com`

Production validation targets are listed in the config, but production automation is disabled and manual review is required before any production validation.

### Recovered program/test constraints

- UAT findings require production reproduction to be bounty-eligible.
- UAT-only information disclosure is nonqualifying in the recovered config.
- Production automated attack techniques are prohibited.
- Only researcher-owned accounts may be used.
- No data modification, privacy violation, DoS, social engineering, brute force, spam or service degradation.
- Production requests require the program's HackerOne research header/email rules; re-check current live brief before using them.
- Evidence policy avoids storing response bodies, secrets, authentication material and PII.
- Aggressive modules are disabled.
- Open-redirect/CORS signals require demonstrated impact before being treated as report candidates.

### Recovered campaign result

An earlier controlled pass used 93 requests across the three UAT targets. The recovered result was dominated by `401/403/404`; no qualifying sensitive/admin/documentation exposure or arbitrary-origin CORS impact was confirmed. Confirmed qualifying findings: **0**.

### Relevant files

- `.github/workflows/syfe-low-impact-recon.yml`
- `.github/workflows/titan-syfe-auth-map.yml`
- `.github/workflows/titan-syfe-deep.yml`
- `bugbounty_runner/config.titan-syfe-uat.json`
- `bugbounty_runner/syfe_auth_surface_map.py`
- `bugbounty_runner/syfe_deep_scan.py`

### Resume point

Read the latest Syfe Actions runs before doing anything. Do not automatically test production. A future candidate found on UAT must first be assessed against the current live program rules and then reproduced on production only in the manually permitted manner required by the program.

---

## 4. Wolt — multi-phase TITAN research

### State

- **Status:** `UNKNOWN_REVIEW_REQUIRED`
- **Confirmed report-ready finding recovered from current continuity evidence:** none

### Recovered in-scope workstream hosts

- `wolt.com`
- `restaurant-api.wolt.com`
- `ops.wolt.com`
- `merchant.wolt.com`
- `drive.wolt.com`
- `corporate.wolt.com`
- `authentication.wolt.com`
- wildcard/app scope was also discussed in prior work; re-check current HackerOne scope before live requests.

### Recovered execution counts

- Phase 1: 120 requests / 48 actions.
- Phase 2: 169 requests / 64 actions.
- Path validation: 6 requests.
- Merchant reflection validation: 2 requests.
- Aggregate recovered count: **297 requests**.
- ScopeGuard blocks: **34**.
- Runner errors: **0**.

These counts prove work was performed; they do not prove a vulnerability.

### Relevant files

- `.github/workflows/titan-wolt-phase1.yml`
- `.github/workflows/titan-wolt-phase2.yml`
- `.github/workflows/titan-wolt-path-validation.yml`
- `.github/workflows/titan-wolt-reflection-validation.yml`
- `bugbounty_runner/config.titan-wolt-phase1.json`
- `bugbounty_runner/config.titan-wolt-phase2.json`
- `bugbounty_runner/validate_wolt_merchant_path.py`
- `bugbounty_runner/validate_wolt_path_norm.py`
- `bugbounty_runner/validate_wolt_reflection.py`
- bridge command JSON files under `bugbounty_runner/bridge/`.

### Bounty snapshot from prior chat

A prior Wolt discussion recorded a Tier-2 style table of approximately **USD 100 / 500 / 1,000 / 2,500** depending on severity, with possible different Tier-1 handling. Treat this only as historical context and re-check the current HackerOne program before using it.

### Resume point

Do not re-run the whole campaign. First inspect the final jobs for the four validation workflows and identify whether any candidate survived the path/reflection controls. If no candidate survived, choose a new hypothesis instead of repeating Phase 1/2.

---

## 5. Other repository workstreams requiring classification/review

The public repository also contains workflows for Klarna, WisdomTree and Polygon. The current recovered evidence is insufficient to safely state their exact platform, current scope, final test verdict or bounty state. Keep them as `UNKNOWN_REVIEW_REQUIRED` until the latest Actions logs and live program pages are re-read.

The private repository `Menorzsda07/Bugbounty-titan-` contains Deribit, Dynatrace and Home Bargains workstreams. Their presence is inventory evidence only. Do not infer they are HackerOne programs without verifying the original program source.

## HackerOne update checklist

For every future HackerOne change, record:

- program/asset;
- live scope check date;
- test account restrictions;
- exact commit/version;
- workflow/run/job IDs;
- result status;
- proof marker;
- impact + limitations;
- report/submission/triage state;
- current bounty table source/date or `unknown`;
- next non-duplicative action.
