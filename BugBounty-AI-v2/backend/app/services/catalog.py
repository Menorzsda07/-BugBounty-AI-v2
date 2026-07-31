from app.models.schemas import TestFamily

CATALOG = [
    TestFamily(id="recon", name="Reconhecimento e superfície", examples=["DNS", "subdomínios", "tecnologias", "endpoints", "parâmetros"], risk="passive"),
    TestFamily(id="xss", name="Cross-Site Scripting", examples=["refletido", "armazenado", "DOM", "contextos HTML/JS"], risk="safe-active"),
    TestFamily(id="injection", name="Injeções", examples=["SQL", "NoSQL", "LDAP", "XPath", "template", "comando"], risk="safe-active"),
    TestFamily(id="authn", name="Autenticação e sessão", examples=["login", "MFA", "reset de senha", "cookies", "tokens"], risk="safe-active"),
    TestFamily(id="authz", name="Autorização", examples=["IDOR/BOLA", "BFLA", "elevação horizontal", "elevação vertical"], risk="safe-active"),
    TestFamily(id="api", name="APIs", examples=["REST", "GraphQL", "WebSocket", "mass assignment", "rate limit"], risk="safe-active"),
    TestFamily(id="ssrf", name="SSRF e requisições do servidor", examples=["SSRF", "open redirect encadeado", "validação de URL"], risk="safe-active"),
    TestFamily(id="xxe", name="XML e parsers", examples=["XXE", "XPath", "parsing inseguro"], risk="safe-active"),
    TestFamily(id="files", name="Arquivos e caminhos", examples=["upload", "path traversal", "LFI", "MIME", "armazenamento público"], risk="safe-active"),
    TestFamily(id="business", name="Lógica de negócio", examples=["cupons", "pagamentos", "limites", "concorrência", "etapas puladas"], risk="safe-active"),
    TestFamily(id="client", name="Cliente e navegador", examples=["CORS", "CSP", "clickjacking", "postMessage", "DOM clobbering"], risk="safe-active"),
    TestFamily(id="secrets", name="Exposição de dados e segredos", examples=["JavaScript", "backups", "debug", "metadados", "erros"], risk="passive"),
    TestFamily(id="infra", name="Infraestrutura e configuração", examples=["TLS", "headers", "DNS", "serviços expostos", "subdomain takeover"], risk="passive"),
    TestFamily(id="deps", name="Dependências", examples=["componentes desatualizados", "CVE aplicável", "bibliotecas cliente"], risk="passive"),
    TestFamily(id="cloud", name="Cloud", examples=["buckets", "IAM", "metadata", "configuração pública"], risk="passive"),
    TestFamily(id="mobile", name="Mobile", examples=["Android", "iOS", "deep links", "armazenamento local", "API móvel"], risk="safe-active"),
]

BLOCKED = ["negação de serviço", "engenharia social", "phishing", "segurança física", "extração de dados reais", "alteração destrutiva"]
