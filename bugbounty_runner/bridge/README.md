# HUNTER8 Bridge

`HUNTER8` is the chat-to-runner command bridge for the BugBounty AI 8-runner scanner.

## Chat command convention

When the user says `HUNTER8` followed by an authorized HackerOne program/domain/scope, ChatGPT should:

1. Review the supplied scope and exclusions.
2. Update the reviewed multi-program config.
3. Update `bugbounty_runner/bridge/command.json` with a new `command_id` and the config path.
4. The GitHub Actions workflow starts automatically on that commit.
5. ChatGPT reads workflow status, job logs and artifacts, then analyzes and validates candidates before calling anything a vulnerability.

## Safety contract

Only explicitly authorized assets go into configs. Program-specific exclusions always override generic modules. Destructive, availability-impacting, credential attacks, social engineering and other disallowed activity are never inferred from a wildcard. Aggressive modules require an explicit program profile permitting the exact technique.

## Status model

- queued: command committed, workflow not started yet
- running: at least one runner active
- analyzing: scanner jobs complete and aggregator running
- complete: combined artifact generated
- candidate: requires manual validation
- validated: reproducible issue with demonstrated impact inside scope
