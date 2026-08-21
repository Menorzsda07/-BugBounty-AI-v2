"""Layered, evidence-first review workflow for authorized bug bounty findings.

The module deliberately separates discovery from acceptance. A detector may create a
candidate, but only the orchestrator can promote it after an independent false-positive
review and an evidence/reproducibility gate.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable
from urllib.parse import urlparse


ANALYST_LAYERS = (
    "scope_guardian",
    "surface_analyst",
    "source_reviewer",
    "auth_analyst",
    "business_logic_analyst",
    "false_positive_reviewer",
    "evidence_analyst",
    "report_reviewer",
)

# Discovery layers create candidates; review layers below decide whether they can
# leave candidate state. Keeping these names explicit makes plans/audit logs stable.
DISCOVERY_LAYER_FAMILIES = {
    "surface_analyst": ("recon", "api", "client"),
    "source_reviewer": ("client", "secrets", "authz", "injection"),
    "auth_analyst": ("authn", "authz", "api"),
    "business_logic_analyst": ("business", "authz"),
}


def layered_plan(enabled_families: Iterable[str]) -> list[dict[str, object]]:
    """Build a stable plan without granting any layer additional authority."""
    enabled = set(enabled_families)
    plan = [{"layer": "scope_guardian", "families": [], "gate": True}]
    for layer, families in DISCOVERY_LAYER_FAMILIES.items():
        plan.append({"layer": layer, "families": [f for f in families if f in enabled], "gate": False})
    plan.extend(
        {"layer": layer, "families": [], "gate": True}
        for layer in ("false_positive_reviewer", "evidence_analyst", "report_reviewer")
    )
    return plan


class ReviewStatus(str, Enum):
    CANDIDATE = "candidate"
    REJECTED = "rejected"
    NEEDS_EVIDENCE = "needs_evidence"
    REVIEWED = "reviewed"
    REPORTABLE = "reportable"


@dataclass(frozen=True)
class Authorization:
    """Immutable authorization passed to every workflow layer."""

    program: str
    assets: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    exclusions: tuple[str, ...] = ()
    expires_at: str | None = None


@dataclass
class Candidate:
    id: str
    title: str
    target: str
    endpoint: str
    family: str
    observed_result: str = ""
    expected_result: str = ""
    reproduction_steps: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    impact_evidence: str = ""
    cwe: str | None = None
    severity: str | None = None
    status: ReviewStatus = ReviewStatus.CANDIDATE
    rejection_reasons: list[str] = field(default_factory=list)
    review_log: list[str] = field(default_factory=list)
    independent_review_passed: bool = False


@dataclass(frozen=True)
class LayerResult:
    layer: str
    passed: bool
    reason: str


class ScopeGuardian:
    name = "scope_guardian"

    def review(self, candidate: Candidate, authorization: Authorization) -> LayerResult:
        # ScopeGuard remains the request-time authority. This is the workflow's
        # second, fail-closed check against the immutable authorization snapshot.
        host = (urlparse(candidate.target if "://" in candidate.target else "https://" + candidate.target).hostname or "").lower()
        def asset_matches(asset: str) -> bool:
            raw = asset.lower().replace("https://", "").replace("http://", "").split("/", 1)[0]
            wildcard = raw.startswith("*.")
            asset_host = raw[2:] if wildcard else raw
            return host == asset_host or (wildcard and host.endswith("." + asset_host))
        in_scope = any(asset_matches(asset) for asset in authorization.assets)
        return LayerResult(self.name, in_scope, "target authorized" if in_scope else "target is not in authorization snapshot")


class FalsePositiveReviewer:
    name = "false_positive_reviewer"

    def review(self, candidate: Candidate, _: Authorization) -> LayerResult:
        missing = []
        if not candidate.observed_result.strip():
            missing.append("observable result")
        if not candidate.expected_result.strip():
            missing.append("expected/control result")
        if candidate.observed_result.strip() == candidate.expected_result.strip():
            missing.append("material difference")
        passed = not missing
        reason = "independent alternative-explanation review passed" if passed else "missing " + ", ".join(missing)
        candidate.independent_review_passed = passed
        return LayerResult(self.name, passed, reason)


class EvidenceAnalyst:
    name = "evidence_analyst"

    def review(self, candidate: Candidate, _: Authorization) -> LayerResult:
        missing = []
        if not candidate.evidence_ids:
            missing.append("captured evidence")
        if len(candidate.reproduction_steps) < 2:
            missing.append("reproduction steps")
        passed = not missing
        return LayerResult(self.name, passed, "evidence is reproducible" if passed else "missing " + ", ".join(missing))


class ReportReviewer:
    name = "report_reviewer"

    def review(self, candidate: Candidate, _: Authorization) -> LayerResult:
        missing = []
        if not candidate.cwe:
            missing.append("CWE")
        if not candidate.severity:
            missing.append("severity")
        if not candidate.impact_evidence.strip():
            missing.append("demonstrated impact")
        passed = not missing
        return LayerResult(self.name, passed, "report metadata and impact validated" if passed else "missing " + ", ".join(missing))


class ReviewOrchestrator:
    """Runs independent gates and promotes only reproducible candidates."""

    def __init__(self, layers: Iterable[object] | None = None) -> None:
        self.layers = list(layers or (ScopeGuardian(), FalsePositiveReviewer(), EvidenceAnalyst(), ReportReviewer()))

    def evaluate(self, candidate: Candidate, authorization: Authorization) -> tuple[Candidate, list[LayerResult]]:
        results: list[LayerResult] = []
        for layer in self.layers:
            result = layer.review(candidate, authorization)
            results.append(result)
            candidate.review_log.append(f"{result.layer}: {'pass' if result.passed else 'fail'} — {result.reason}")
            if not result.passed:
                candidate.rejection_reasons.append(result.reason)

        failed_layers = {r.layer for r in results if not r.passed}
        if not failed_layers:
            candidate.status = ReviewStatus.REPORTABLE
        elif "scope_guardian" in failed_layers or "false_positive_reviewer" in failed_layers:
            candidate.status = ReviewStatus.REJECTED
        else:
            candidate.status = ReviewStatus.NEEDS_EVIDENCE
        return candidate, results


review_orchestrator = ReviewOrchestrator()
