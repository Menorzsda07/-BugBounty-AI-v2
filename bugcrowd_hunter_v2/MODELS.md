# Optional multi-model consensus

When an `OPENAI_API_KEY` GitHub Actions secret is present, candidate evidence can be reviewed by multiple GPT models independently. The tool first lists the account's available models and chooses compatible GPT-family models dynamically.

Recommended roles:
- fast reviewer: triage large candidate sets and reject obvious false positives;
- deep reviewer: reason about authorization, protocol and business-logic impact;
- judge: compare the independent reviews and select the smallest next validation step.

All input must already be redacted. Model outputs are advisory and cannot change the scope allowlist, send target traffic, or mark a finding report-ready without deterministic evidence.
