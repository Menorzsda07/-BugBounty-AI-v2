from __future__ import annotations
from datetime import datetime, timezone
from typing import Literal
from pydantic import BaseModel, Field

Status = Literal["queued", "validating_scope", "planning", "running", "completed", "blocked", "failed"]
FindingState = Literal["confirmed", "probable", "inconclusive", "informational", "false_positive"]

class ChatRequest(BaseModel):
    message: str = Field(min_length=2, max_length=4000)
    conversation_id: str | None = None

class ScopeDecision(BaseModel):
    target: str
    authorized: bool
    program_handle: str | None = None
    matched_asset: str | None = None
    reason: str

class TestFamily(BaseModel):
    id: str
    name: str
    examples: list[str]
    risk: Literal["passive", "safe-active", "intrusive", "destructive"]
    enabled: bool = True

class EvidenceItem(BaseModel):
    type: Literal["screenshot", "request", "response", "har", "console", "metadata", "hash"]
    filename: str
    description: str
    sha256: str | None = None

class Finding(BaseModel):
    id: str
    title: str
    family: str
    state: FindingState
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: int = Field(ge=0, le=100)
    target: str
    endpoint: str
    summary: str
    observed_result: str
    expected_result: str
    impact: str
    remediation: list[str]
    evidence: list[EvidenceItem] = []
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class Investigation(BaseModel):
    id: str
    conversation_id: str
    target: str
    status: Status
    progress: int = Field(ge=0, le=100)
    current_step: str
    plan: list[TestFamily]
    layered_workflow: list[dict] = []
    findings: list[Finding] = []
    timeline: list[str] = []
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class ChatResponse(BaseModel):
    conversation_id: str
    reply: str
    investigation: Investigation | None = None
    actions: list[str] = []
