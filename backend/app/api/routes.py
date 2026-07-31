from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from app.models.schemas import ChatRequest, ChatResponse
from app.services.orchestrator import orchestrator
from app.services.catalog import CATALOG, BLOCKED
from app.services.reporting import markdown_report

router = APIRouter(prefix="/api")

@router.get("/health")
def health():
    return {"status": "ok", "mode": "safe-demo"}

@router.get("/coverage")
def coverage():
    return {"families": [item.model_dump() for item in CATALOG], "blocked": BLOCKED}

@router.post("/chat", response_model=ChatResponse)
def chat(request: ChatRequest):
    return orchestrator.handle(request.message, request.conversation_id)

@router.get("/investigations/{investigation_id}")
def investigation(investigation_id: str):
    item = orchestrator.investigations.get(investigation_id)
    if not item:
        raise HTTPException(404, "Investigação não encontrada.")
    return item

@router.get("/investigations/{investigation_id}/report", response_class=PlainTextResponse)
def report(investigation_id: str):
    item = orchestrator.investigations.get(investigation_id)
    if not item:
        raise HTTPException(404, "Investigação não encontrada.")
    return markdown_report(item)
