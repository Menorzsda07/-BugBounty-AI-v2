# BugBounty AI v2

Plataforma conversacional para organizar investigações de bug bounty **somente em ativos autorizados**. O domínio é informado diretamente no chat; o sistema valida o escopo, monta um plano amplo, acompanha a execução e apresenta achados detalhados com evidências.

## Continuidade para ChatGPT/Codex

Se você conectou uma nova sessão/conta do ChatGPT ou Codex a este repositório para continuar as pesquisas de bug bounty, **não comece do zero**.

Leia primeiro:

1. [`AGENTS.md`](AGENTS.md) — regras de retomada e atualização.
2. [`CHATGPT_BUG_BOUNTY_CONTINUITY.md`](CHATGPT_BUG_BOUNTY_CONTINUITY.md) — índice canônico do estado atual.
3. [`docs/continuity/HACKERONE.md`](docs/continuity/HACKERONE.md) — workstreams HackerOne.
4. [`docs/continuity/BUGCROWD.md`](docs/continuity/BUGCROWD.md) — workstreams Bugcrowd.
5. [`docs/continuity/state.json`](docs/continuity/state.json) — estado estruturado para agentes.

Esses arquivos registram o que já foi testado, resultados negativos, bugs confirmados/report-ready, evidências, runs/commits, limitações, bounty snapshots e o próximo ponto seguro de retomada. HackerOne e Bugcrowd devem permanecer separados.

## O que está implementado

- Interface responsiva estilo ChatGPT, adequada para iPhone.
- Entrada do domínio diretamente no chat.
- Scope Guard que bloqueia alvos não autorizados.
- Catálogo de cobertura: XSS, SQL/NoSQL e outras injeções, autenticação, IDOR/BOLA, APIs, SSRF, XXE, uploads, lógica de negócio, CORS/CSP, infraestrutura, dependências, cloud e mobile.
- Orquestrador de investigação em modo seguro de demonstração.
- Linha do tempo e progresso.
- Achado técnico detalhado com estado, severidade, confiança, resultado observado, impacto e correção.
- Evidências com request, response, metadados e SHA-256.
- Relatório Markdown por investigação.
- API FastAPI e testes automatizados.
- Prévia offline para abrir no iPhone: `preview-iphone.html`.

## Limite honesto desta entrega

A arquitetura, a interface, o fluxo de escopo, o catálogo, o armazenamento de evidências e os relatórios estão funcionais. A execução real de scanners e navegadores automatizados não foi ativada. Isso exige hospedar o backend, conectar as contas, importar a política de cada programa e habilitar agentes individualmente com limites de requisição e controles de segurança.

A prévia usa evidências sintéticas claramente identificadas. Ela não afirma encontrar bugs reais.

## Executar no computador ou servidor

```bash
cd backend
python -m venv .venv
source .venv/bin/activate       # Linux/macOS
# .venv\Scripts\activate      # Windows
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Abra `http://localhost:8000`.

## Testar

```bash
cd backend
pytest -q
```

## Demonstração

No modo atual, use no chat:

```text
Analise https://example.com procurando todas as vulnerabilidades permitidas
```

Outros domínios são bloqueados até a integração real com a HackerOne estar configurada.

## Segurança

- Nunca armazene tokens em arquivos enviados ou no Git.
- Gere um token novo para a HackerOne; um token anteriormente compartilhado em conversa não foi incluído neste projeto.
- Mantenha submissão de relatório sob revisão humana.
- Bloqueie DoS, engenharia social, phishing, extração de dados e alterações destrutivas.

## Deploy no Render

O projeto inclui `Dockerfile` e `render.yaml`. Depois de enviar ao GitHub, crie um Blueprint no Render, selecione o repositório e mantenha `SAFE_DEMO_MODE=true` no primeiro deploy. Consulte `DEPLOY_IPHONE.md`.
