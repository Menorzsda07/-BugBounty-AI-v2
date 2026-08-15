# Bugcrowd Hunter V2

Separate Bugcrowd-focused research pipeline. It does not modify or depend on the `Bugbounty-titan-` repository.

Pipeline:
1. Scope guard: exact allowlists and per-program restrictions.
2. Deterministic recon: HTTP, JS, source maps, OpenAPI/GraphQL, auth boundaries, CORS/cache, path/method behavior.
3. Candidate extraction: source-to-sink paths, endpoint/object identifiers, authorization boundaries, OAuth/session flows.
4. Targeted validation: only minimal requests needed to confirm impact; no destructive exploitation.
5. Optional LLM consensus: multiple OpenAI models independently classify candidates, then a judge model merges the opinions. LLM output never expands scope and never directly sends network requests.
6. Evidence pack: reproducible request/response metadata, redacted secrets/PII, confidence, impact, duplicate-risk notes.

The LLM layer is optional and enabled only when `OPENAI_API_KEY` is configured as a GitHub Actions secret. Model IDs are resolved from the account's available model list, so the pipeline does not assume every account has the same model access.
