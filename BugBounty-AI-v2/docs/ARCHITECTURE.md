# Arquitetura

Chat → interpretação do alvo → Scope Guard → política do programa → planejador → agentes especializados → correlação → validação mínima → Evidence Store → relatório.

## Agentes planejados

- Recon Agent
- Web Discovery Agent
- XSS Agent
- Injection Agent
- Authentication Agent
- Authorization Agent
- API/GraphQL Agent
- SSRF/Parser Agent
- File/Upload Agent
- Business Logic Agent
- Client Security Agent
- Infrastructure/Cloud Agent
- Mobile Agent
- Evidence Agent
- Reporting Agent

Cada agente deve receber uma autorização imutável contendo programa, ativos, métodos permitidos, limites, exclusões e prazo. Toda requisição deve passar novamente pelo Scope Guard.
