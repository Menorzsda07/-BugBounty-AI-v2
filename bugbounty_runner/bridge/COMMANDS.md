# TITAN Chat Command Interface

This file defines the chat-side control language for the HUNTER8 / TITAN bug-bounty runner bridge.

## Commands

### /inicie titan <target/program> <scope/rules>
Purpose: start a new authorized scan job.
Chat behavior:
1. Parse the program/domain, eligible assets, exclusions and program rules supplied by the user.
2. Reject or hold any target that is not explicitly authorized or whose scope is ambiguous.
3. Normalize the supplied scope into the multi-program scanner configuration.
4. Send/update the command for the 8-runner scanner.
5. Track the resulting workflow run and analyze its final artifacts.

### /atualize
Purpose: status / blockers.
Return what remains to be done for each active job: pending runners, failed runners, missing scope information, missing test account/tenant requirements, pending aggregation or pending manual validation.

### /Detalhes
Purpose: detailed progress report.
Return, per active target/program: what was completed, what is running now, runner/module progress, useful counts, errors/retries, current candidates, and a rough ETA when an estimate can be grounded in elapsed/current runner progress. Do not invent an ETA if the available run state does not support one.

### /Add <target/program> <scope/rules>
Purpose: add another authorized program/domain while existing jobs may continue.
Parse and validate the new program independently, keep program-specific exclusions separated, add it to the multi-program queue/config, and start/queue scanning without mixing scopes.

### /info
Purpose: program/target inventory.
Return identifiable names for programs/domains and their state: queued, running, completed, blocked, failed, or awaiting manual validation. Include completed domains so the user can reference them later by name.

### /vuln <target-name>
Purpose: vulnerability report for one named target/program.
Return only findings associated with that target. Separate: validated vulnerabilities, candidates awaiting manual validation, informational recon, rejected/false positives. For validated items include description, impact, evidence/reproduction summary, likely severity, affected asset, and bounty status/estimate only when grounded in the applicable program rules. Never label a scanner hit as validated without confirmation.

## Aliases / name key
Primary command key: TITAN
Scanner engine: HUNTER8
The user can refer to the system simply as "Titan".

## Safety / scope invariant
Every scan must be bound to an explicit authorized scope/allowlist. Program exclusions and path exclusions must remain isolated per program. Potentially disruptive modules are disabled unless the supplied program rules explicitly authorize them. Findings are candidates until independently validated.
