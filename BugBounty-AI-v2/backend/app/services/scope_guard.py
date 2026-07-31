from __future__ import annotations
from urllib.parse import urlparse
from app.models.schemas import ScopeDecision

DEMO_SCOPES = {
    "demo-program": ["*.example.com", "api.example.com", "https://example.com"],
}

def normalize_host(target: str) -> str:
    value = target.strip()
    parsed = urlparse(value if "://" in value else f"https://{value}")
    return (parsed.hostname or "").lower().rstrip(".")

def matches(host: str, asset: str) -> bool:
    candidate = asset.replace("https://", "").replace("http://", "").split("/")[0].lower()
    if candidate.startswith("*."):
        suffix = candidate[2:]
        return host == suffix or host.endswith("." + suffix)
    return host == candidate

class ScopeGuard:
    def validate_demo(self, target: str) -> ScopeDecision:
        host = normalize_host(target)
        if not host:
            return ScopeDecision(target=target, authorized=False, reason="Não foi possível identificar um domínio válido.")
        for program, assets in DEMO_SCOPES.items():
            for asset in assets:
                if matches(host, asset):
                    return ScopeDecision(target=target, authorized=True, program_handle=program, matched_asset=asset, reason="O alvo corresponde a um ativo autorizado no modo de demonstração.")
        return ScopeDecision(target=target, authorized=False, reason="O domínio não corresponde a nenhum escopo autorizado disponível. Conecte a HackerOne ou use example.com na demonstração.")

scope_guard = ScopeGuard()
