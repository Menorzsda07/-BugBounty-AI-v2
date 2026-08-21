from app.services.review_workflow import (
    ANALYST_LAYERS,
    Authorization,
    Candidate,
    ReviewStatus,
    layered_plan,
    review_orchestrator,
)


def authorization():
    return Authorization(program="demo", assets=("*.example.com", "example.com"), allowed_actions=("passive", "safe-active"))


def valid_candidate():
    return Candidate(
        id="c-1", title="Cross-account object read", target="https://api.example.com", endpoint="/objects/2",
        family="authz", observed_result="user A received user B's object", expected_result="403 for foreign object",
        reproduction_steps=["Authenticate as user A", "Request object owned by user B"],
        evidence_ids=["request-a", "response-a"], impact_evidence="A second account's private object was returned",
        cwe="CWE-639", severity="high",
    )


def test_plan_contains_all_independent_layers():
    plan = layered_plan(["recon", "api", "authn", "authz", "business", "client", "secrets"])
    assert tuple(item["layer"] for item in plan) == ANALYST_LAYERS
    assert plan[0]["gate"] is True


def test_reproducible_candidate_becomes_reportable():
    candidate, results = review_orchestrator.evaluate(valid_candidate(), authorization())
    assert candidate.status == ReviewStatus.REPORTABLE
    assert candidate.independent_review_passed
    assert all(result.passed for result in results)


def test_looks_insecure_is_not_enough():
    candidate = valid_candidate()
    candidate.observed_result = ""
    candidate.evidence_ids = []
    reviewed, _ = review_orchestrator.evaluate(candidate, authorization())
    assert reviewed.status == ReviewStatus.REJECTED
    assert reviewed.rejection_reasons


def test_out_of_scope_candidate_fails_closed():
    candidate = valid_candidate()
    candidate.target = "https://example.net"
    reviewed, _ = review_orchestrator.evaluate(candidate, authorization())
    assert reviewed.status == ReviewStatus.REJECTED
