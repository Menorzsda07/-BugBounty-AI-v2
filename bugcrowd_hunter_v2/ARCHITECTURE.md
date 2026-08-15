# Bugcrowd Hunter V2 Architecture

This engine is separated from HackerOne/Titan campaigns and from individual Bugcrowd target branches.

## Stages

- `scope`: exact host/path allowlists plus engagement-specific prohibited techniques.
- `recon`: passive/static discovery and bounded HTTP checks.
- `analyze`: JavaScript/API/OAuth/session/object-identifier analysis.
- `hypothesize`: rank source-to-sink, BOLA/IDOR, auth boundary, business-logic and exposure candidates.
- `validate`: run only the smallest permitted request sequence needed to prove or reject impact.
- `consensus`: optional multi-model review of redacted evidence; models never issue network requests or expand scope.
- `evidence`: retain metadata and minimal reproducible evidence while excluding secrets and third-party PII.

## Candidate state

`info -> candidate -> reproducible -> impact_validated -> report_ready`

A finding may only become `report_ready` when the observed behavior, reproducibility and security impact are all evidenced. Model opinion cannot promote a finding by itself.
