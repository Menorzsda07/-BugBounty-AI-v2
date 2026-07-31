from __future__ import annotations
import re, uuid
from app.models.schemas import ChatResponse, Investigation, Finding
from app.services.catalog import CATALOG, BLOCKED
from app.services.scope_guard import scope_guard
from app.services.evidence import evidence_store

TARGET_RE = re.compile(r"(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?")

class Orchestrator:
    def __init__(self) -> None:
        self.investigations: dict[str, Investigation] = {}

    def handle(self, message: str, conversation_id: str | None = None) -> ChatResponse:
        cid = conversation_id or f"conv-{uuid.uuid4().hex[:10]}"
        match = TARGET_RE.search(message)
        if not match:
            return ChatResponse(conversation_id=cid, reply="Envie um domínio autorizado no chat, por exemplo: ‘Analise https://example.com procurando todas as vulnerabilidades permitidas’. Eu validarei o escopo antes de montar o plano.", actions=[])

        target = match.group(0).rstrip(".,;)")
        decision = scope_guard.validate_demo(target)
        if not decision.authorized:
            return ChatResponse(conversation_id=cid, reply=f"Não iniciei a investigação. {decision.reason}", actions=["Conectar HackerOne", "Informar outro alvo autorizado"])

        inv_id = f"inv-{uuid.uuid4().hex[:8]}"
        timeline = [
            "Escopo validado.",
            "Política de segurança aplicada.",
            f"Plano criado com {len(CATALOG)} famílias de teste.",
            "Testes destrutivos e fora de escopo bloqueados.",
            "Demonstração concluída sem executar exploração real.",
        ]
        evidence = [
            evidence_store.save_text(inv_id, "request.txt", "GET / HTTP/1.1\nHost: example.com\nUser-Agent: BugBounty-AI-v2-demo\n", "request", "Requisição HTTP sanitizada da demonstração."),
            evidence_store.save_text(inv_id, "response.txt", "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><title>Example Domain</title></html>\n", "response", "Resposta HTTP sanitizada da demonstração."),
            evidence_store.save_metadata(inv_id, {"target": target, "program": decision.program_handle, "mode": "demo", "blocked": BLOCKED}),
        ]
        finding = Finding(
            id=f"finding-{uuid.uuid4().hex[:8]}",
            title="Cabeçalhos defensivos ausentes (demonstração)",
            family="client",
            state="informational",
            severity="info",
            confidence=100,
            target=target,
            endpoint="/",
            summary="A demonstração ilustra o formato detalhado de um achado e das evidências. Ela não afirma uma vulnerabilidade real no alvo.",
            observed_result="A resposta de demonstração não inclui cabeçalhos defensivos no arquivo de evidência sintético.",
            expected_result="Aplicações reais devem definir cabeçalhos compatíveis com seu contexto e política.",
            impact="Informativo. Nenhum impacto real foi validado nesta demonstração.",
            remediation=["Revisar CSP, frame-ancestors, Referrer-Policy e Permissions-Policy.", "Validar compatibilidade antes da implantação."],
            evidence=evidence,
        )
        investigation = Investigation(id=inv_id, conversation_id=cid, target=target, status="completed", progress=100, current_step="Demonstração concluída", plan=CATALOG, findings=[finding], timeline=timeline)
        self.investigations[inv_id] = investigation

        reply = (
            f"Escopo autorizado no programa {decision.program_handle}. Montei uma investigação ampla com {len(CATALOG)} famílias: XSS, SQL/NoSQL e outras injeções, IDOR/BOLA, autenticação, APIs, SSRF, XXE, uploads, lógica de negócio, CORS/CSP, infraestrutura, cloud, mobile e dependências.\n\n"
            "Esta instalação está em modo de demonstração: ela mostra o fluxo, o relatório detalhado e a preservação de evidências, mas não dispara scanners nem payloads reais. Para execução real, cada agente deve ser habilitado apenas após importar a política do programa, limites e exclusões."
        )
        return ChatResponse(conversation_id=cid, reply=reply, investigation=investigation, actions=["Ver evidências", "Gerar relatório", "Continuar investigação"])

orchestrator = Orchestrator()
