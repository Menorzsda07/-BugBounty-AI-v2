from app.services.scope_guard import normalize_host, matches, scope_guard
from app.services.catalog import CATALOG
from app.services.orchestrator import orchestrator


def test_scope_matching():
    assert normalize_host("https://api.example.com/path") == "api.example.com"
    assert matches("a.example.com", "*.example.com")
    assert not matches("example.net", "*.example.com")


def test_catalog_is_broad():
    ids = {f.id for f in CATALOG}
    assert {"xss", "injection", "authz", "authn", "ssrf", "api", "business", "mobile", "cloud"}.issubset(ids)


def test_out_of_scope_is_blocked():
    result = scope_guard.validate_demo("not-authorized.invalid")
    assert result.authorized is False


def test_chat_creates_detailed_demo_investigation():
    response = orchestrator.handle("Analise https://example.com procurando tudo")
    assert response.investigation is not None
    assert response.investigation.status == "completed"
    assert response.investigation.findings[0].evidence
