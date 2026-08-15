# Bug bounty continuity instructions

This repository is used as the persistent continuity source for authorized bug-bounty research performed with ChatGPT/Codex.

## Read this first

Before starting or resuming any bug-bounty work, read these files in order:

1. `CHATGPT_BUG_BOUNTY_CONTINUITY.md`
2. `docs/continuity/HACKERONE.md` when the program is on HackerOne
3. `docs/continuity/BUGCROWD.md` when the program is on Bugcrowd
4. `docs/continuity/state.json` for the machine-readable current state
5. The relevant workflow/config/PoC files referenced by the program entry

Do not start a program from zero until the continuity files and the latest relevant GitHub Actions runs have been checked.

## Platform isolation is mandatory

HackerOne and Bugcrowd are independent workstreams. Never mix:

- program scope;
- program rules;
- evidence;
- reports;
- bounty tables;
- triage history;
- account/test requirements;
- conclusions from one platform/program into another.

Each program must also remain an independent workstream even when the same repository/runner is used.

## Finding status vocabulary

Use these labels consistently:

- `CONFIRMED_REPORT_READY`: security impact reproduced with sufficient evidence and a report package exists or can be assembled from recorded evidence.
- `CONFIRMED_SUBMITTED`: submitted to the platform; do not imply acceptance unless triage has explicitly done so.
- `ACCEPTED`: program/triage explicitly accepted the issue.
- `CANDIDATE`: interesting behavior, impact not yet proven.
- `NEGATIVE`: tested and the expected security control worked or the hypothesis was disproved.
- `PLANNED`: not executed yet.
- `UNKNOWN_REVIEW_REQUIRED`: repository artifacts exist, but the latest chat/Actions outcome was not recovered with enough confidence.

Never upgrade a `CANDIDATE`, `NEGATIVE`, `PLANNED`, or `UNKNOWN_REVIEW_REQUIRED` item to a vulnerability without new evidence.

## Resume protocol

When resuming a workstream:

1. Re-check the current public program scope/rules before making live requests.
2. Read the latest program entry in the continuity docs.
3. Inspect the most recent relevant workflow run and job log before repeating a test.
4. Prefer a new hypothesis over re-running a closed `NEGATIVE` path unless the target code/version materially changed.
5. Use only explicitly in-scope assets and researcher-owned/provided test accounts.
6. Stop immediately if real third-party/customer data is encountered and follow the program's reporting rules.
7. Do not perform DoS, destructive actions, social engineering, credential attacks, spam, or excessive automation unless a program explicitly authorizes that exact activity.
8. Preserve evidence identifiers (commit SHA, workflow name, run ID, job ID, artifact ID/hash) but never commit credentials, bearer tokens, cookies, refresh tokens, API keys, raw PII, or other secrets.

## Update protocol after every meaningful test

Update the relevant platform document and `docs/continuity/state.json` with:

- date;
- platform and program;
- asset/scope used;
- hypothesis tested;
- workflow/file name;
- commit SHA;
- workflow run/job IDs when available;
- result (`CONFIRMED_*`, `CANDIDATE`, `NEGATIVE`, etc.);
- demonstrated impact and important limitations;
- bounty/severity estimate only when grounded in the program table or clearly marked as an estimate;
- next non-duplicative step.

## Repository safety

`Menorzsda07/-BugBounty-AI-v2` is the canonical continuity repository. Some evidence/workflows also exist in `Menorzsda07/Bugbounty-titan-`, including a GitLab validation branch. Treat the latter as a referenced evidence repository unless the user explicitly asks for changes there.

The continuity documents are sanitized summaries. Raw proof artifacts should remain separate and should be credential-scanned before sharing or committing.
