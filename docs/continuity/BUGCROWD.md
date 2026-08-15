# Bugcrowd Continuity Record

**Last consolidated:** 2026-08-15  
**Rule:** this file contains Bugcrowd workstreams only. Do not import HackerOne scope, account conventions, headers, bounty tables, reports, or triage history into this file.

## 1. Skyscanner — active research workstream

### Current state

- **Platform:** Bugcrowd
- **Program:** Skyscanner
- **Status through the latest completed hypothesis:** `NEGATIVE`
- **Latest completed research version:** v36
- **Latest consolidation commit on main:** `e38163b13751e40b3a1969f98f82da48a68b884f`
- **Confirmed reportable vulnerabilities recovered through v36:** **0**
- **Confirmed bounty from findings so far:** **USD 0**
- **Next recorded hypothesis:** `PLANNED`, not yet executed

### Program rules recovered on 2026-08-15

Before any future request, re-check the live Bugcrowd brief because rules can change. The recovered brief required/established:

- add HTTP header `Skyscanner-Security: Bugcrowd` to research requests;
- test only areas explicitly in scope;
- interact only with researcher-owned accounts or provided test accounts;
- avoid privacy violations, data destruction and service interruption/degradation;
- stop and report immediately if real traveller/customer data is encountered; do not view, alter, save, store or transfer it;
- social engineering is prohibited;
- DDoS is prohibited;
- excessive automated vulnerability/scanning activity is prohibited;
- do not spam forms or account-creation flows;
- testing corporate `*@skyscanner.net` email is prohibited;
- the first submitted report of a vulnerability is the one eligible for monetary reward under the recovered brief;
- coordinated disclosure rules apply.

The research in this repository was deliberately kept low-impact and used controlled identities when authentication/identity behavior was tested.

### Recovered reward table snapshot — 2026-08-15

| Priority | Reward range |
|---|---:|
| P1 | **USD 3,000–8,000** |
| P2 | **USD 900–3,000** |
| P3 | **USD 300–500** |
| P4 | **USD 100–150** |

The brief stated that higher rewards are reserved for high business criticality and that valid Focus Area submissions may receive greater bounties. Final priority and payment remain Bugcrowd/Skyscanner decisions.

Historical public program metadata recovered by the target-info workflow at this snapshot also showed 196 rewarded vulnerabilities, an average payout of approximately USD 1,714.28 and a displayed validation time of about 13 days. Treat those as dated program statistics, not a prediction for any submission.

### Scope handling

The workstream has touched/reviewed Skyscanner web/mobile surfaces such as the main Skyscanner site, Partner Portal, gateway/mobile API routes and the official Android app. Some earlier scope reconstruction also included wildcard Skyscanner assets, mobile applications and infrastructure categories.

Do **not** treat this paragraph as a permanent allowlist. A future agent must re-open the current Bugcrowd Target Information before live testing and use the current target table as source of truth.

---

## Research chronology and what has already been done

The workflow filenames are intentionally preserved because they are the best audit trail for a future agent. The list below groups the work so that already-covered paths are not restarted from zero.

### v1–v3: rules, scope and bounty baseline

Relevant workflows:

- `.github/workflows/bugcrowd-skyscanner-manual-baseline-v1.yml`
- `.github/workflows/bugcrowd-skyscanner-scope-extract-v2.yml`
- `.github/workflows/bugcrowd-skyscanner-target-info-v3.yml`

Work performed:

- created a rule-compliant manual baseline;
- extracted public Bugcrowd engagement metadata;
- recovered rules, reward ranges, Safe Harbor context and public statistics;
- established the required `Skyscanner-Security: Bugcrowd` header and restrictions before active testing.

Result: setup/recon only; no vulnerability by itself.

### v4–v7: Android package discovery/acquisition

Relevant commits/workflows include package discovery, public mirror/download route inspection and acquisition of the current Skyscanner Android package.

Examples:

- `bugcrowd-skyscanner-android-download-route-v6.yml`
- Android discovery/acquisition workflows around v4–v7

Work performed:

- identified a current official Android package route/source;
- acquired the package for static inspection;
- used package contents as the basis for later deep-link, OAuth, exported-component and API-client analysis.

Result: recon only; no reportable issue recorded.

### v8–v19: Android application security surfaces + Partner Portal/OAuth

Covered families:

- Android deep links/app links;
- exported components;
- XML/network security configuration;
- OAuth routing/proxy behavior;
- targeted routing classes;
- FileProvider/deep-link parser;
- Partner Portal baseline;
- `returnUrl` handling;
- OAuth callback state binding;
- Okta callback validation;
- gateway endpoint strings;
- exported component inventory;
- Partner Portal host-header poisoning check later at v33.

Representative workflow/commit names:

- `test: inspect Skyscanner Android deeplink and OAuth routing v8`
- `test: validate Skyscanner Android app-link bindings v9`
- `test: baseline Skyscanner OAuth callback behavior v10`
- `test: decompile targeted Skyscanner Android routing classes v11`
- `test: inspect Skyscanner Android security XML config v12`
- `test: baseline Skyscanner Partner Portal v13`
- `test: validate Partner Portal returnUrl handling v14`
- `test: inspect Partner Portal OAuth callback state binding v15`
- `test: inspect exported OAuth router proxy behavior v16`
- `test: inspect Skyscanner Okta callback validation v17`
- `recon: extract Skyscanner gateway endpoint strings v18`
- `audit: enumerate Skyscanner Android exported components v19`
- `test: check Partner Portal OAuth host-header poisoning v33`

Recovered overall conclusion: these paths did not produce a confirmed reportable vulnerability in the current workstream. Do not repeat them wholesale unless the app/portal behavior materially changes or a new concrete exploit chain is identified.

### v20–v27: account APIs, Saved experience authorization and CORS

Representative commits/workflows:

- `recon: decompile Skyscanner account and Saved API clients v20`
- `test: baseline Skyscanner account API authorization v21`
- `recon: extract Skyscanner Saved object identifiers v22`
- `test: compare Skyscanner Saved reads across anonymous sessions v23`
- `recon: inspect Skyscanner web API route strings v24`
- `test: check Skyscanner authenticated API CORS v25`
- `recon: trace Skyscanner Saved IDs and capability tokens v26`
- `test: verify Skyscanner Saved mutation auth gates v27`

Work performed:

- mapped account/Saved client routes and identifiers;
- compared anonymous-session read behavior;
- checked authorization baselines;
- checked mutation gates;
- examined capability-token usage;
- checked authenticated API CORS behavior.

Recovered overall conclusion: no confirmed cross-account access, unauthorized Saved mutation or exploitable CORS issue was established. These are closed/negative families unless new evidence appears.

### v28–v34: anonymous auth, unsubscribe capability and identity internals

Representative commits/workflows:

- `recon: trace Skyscanner anonymous auth client v28`
- `test: verify Skyscanner unsubscribe capability token enforcement v29`
- `test: baseline Skyscanner anonymous auth token contract v30`
- `recon: resolve Skyscanner anonymous auth string xrefs v31`
- `recon: inspect Skyscanner anonymous auth config defaults v32`
- `test: check Partner Portal OAuth host-header poisoning v33`
- `recon: locate Skyscanner anonymous identity classes v34`

Static/recon observations from the official Android package included anonymous-identity classes/config keys such as:

- `AnonymousAuthStateProvider`
- `AnonymousIdentitySharedPreferences`
- `AnonymousIdentityTokens`
- anonymous authorization/token endpoint configuration keys
- anonymous client ID/grant/redirect/scope configuration keys
- trusted-anonymous/UTID related configuration strings

These strings/configs are attack-surface clues, **not vulnerabilities by themselves**.

The anonymous token flow was then tested using controlled identities rather than third-party accounts.

---

## Key completed negative tests

### v35 — two controlled anonymous identities

**Status:** `NEGATIVE`  
**Finding bounty:** **USD 0**

Workflow:

- `.github/workflows/bugcrowd-skyscanner-anonymous-two-identities-v35.yml`
- commit: `d365a8aa6503ef222ca2624deb0dee28684e67e7`
- workflow run recovered: `31903201446`
- job recovered: `95057010225`

What the workflow did:

1. Created anonymous identity A using a random researcher-controlled `previous_utid` seed.
2. Created anonymous identity B independently.
3. Received anonymous access and refresh credentials for each.
4. Confirmed their access-token UTID claims were distinct.
5. Used each identity against protected endpoints for:
   - Saved list;
   - Price Alerts;
   - current authenticated identity.

Observed result:

- Saved list -> `401`
- Price Alerts -> `401`
- identity current -> `401`

for both A and B.

Interpretation: anonymous credentials did not satisfy endpoints requiring authenticated user access. The expected authorization boundary held. No cross-identity data or protected account state was obtained.

Do not report this behavior as a bug and do not re-run it without a new differentiating hypothesis.

### v36 — controlled `previous_utid` reclaim attempt

**Status:** `NEGATIVE`  
**Finding bounty:** **USD 0**

Workflow/commit:

- `.github/workflows/bugcrowd-skyscanner-anonymous-utid-reclaim-v36.yml`
- commit: `e38163b13751e40b3a1969f98f82da48a68b884f`
- recovered run discussed in chat: `31903244954`

Hypothesis:

Could a researcher submit the UTID of a previously created controlled anonymous identity through `previous_utid` and cause the service to reclaim/reissue that earlier identity in a way that creates an identity-takeover primitive?

Recovered result:

- repeated requests did **not** restore/reuse the earlier controlled identity;
- the service generated new identity/UTID values instead;
- no takeover/reclaim effect was demonstrated.

Interpretation: hypothesis disproved under the tested conditions.

Do not report it as a vulnerability.

---

## Next non-duplicative research point

### v37 candidate — anonymous refresh-token identity binding

**Status:** `PLANNED` — **not executed as of this consolidation**.

Goal:

Using only two independently created researcher-controlled anonymous identities, determine whether an anonymous refresh token remains cryptographically/logically bound to its originating identity and client context.

Security condition of interest:

- a genuine bug would require a controlled cross-identity result such as refresh material from A being accepted in a way that produces B's identity/state, crosses an authorization boundary, or creates another reproducible identity-confusion impact;
- a normal refresh of A back into A, or clean rejection of mismatched state, is `NEGATIVE`.

Safety boundary:

- only controlled anonymous identities;
- no third-party UTIDs/tokens/data;
- no brute force or token guessing;
- no high-rate automation;
- use mandatory Bugcrowd header;
- stop on any unexpected real traveller data.

Before running, derive the exact refresh grant request contract from the already-downloaded official client/package or a current official client version. Do not guess parameters at scale.

---

## Current Skyscanner bug/bounty ledger

| Item | Status | Priority estimate | Bounty state |
|---|---|---|---:|
| Android/OAuth/Partner Portal surface families through v34 | No confirmed issue recovered | N/A | USD 0 confirmed |
| v35 two anonymous identities | `NEGATIVE` | N/A | USD 0 |
| v36 `previous_utid` reclaim | `NEGATIVE` | N/A | USD 0 |
| v37 refresh-token binding | `PLANNED` | unknown | not applicable until executed |

If a future test becomes a real finding, add it here immediately with the program's priority range beside it. Do not show the program-wide maximum as though it were the expected payout for an unvalidated candidate.

## Evidence hygiene

The public continuity repository must never contain:

- raw access tokens;
- raw refresh tokens;
- cookies/session IDs;
- live API keys;
- researcher passwords;
- real traveller/customer PII;
- third-party identifiers obtained outside the allowed research boundary.

Store only redacted claims, lengths, status codes, safe identifiers, commits, workflow/run/job IDs and sanitized proof descriptions.

## Bugcrowd update checklist

For every new Skyscanner test, append/update:

- live scope/brief check date;
- mandatory-header use;
- exact controlled account/identity model without secret values;
- hypothesis;
- workflow + commit + run + job;
- result status;
- impact/limitations;
- bounty estimate based on the current Skyscanner P1–P4 table;
- next non-duplicative step.

If a finding is submitted, change its status to `CONFIRMED_SUBMITTED`; only use `ACCEPTED` after explicit Bugcrowd/Skyscanner confirmation.
