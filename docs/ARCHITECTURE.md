# Arquitetura

Chat → interpretação do alvo → Scope Guard → política do programa → planejador → agentes especializados → correlação → validação mínima → Evidence Store → relatório.

## Workflow em camadas (implementado)

1. **Scope Guardian** valida uma autorização imutável e falha de forma fechada.
2. **Surface Analyst** organiza superfície web/API/cliente.
3. **Source Reviewer** revisa código e JavaScript importados.
4. **Auth Analyst** compara identidades, funções e estados de sessão.
5. **Business-Logic Analyst** avalia transições e invariantes de fluxo.
6. **False-Positive Reviewer** exige diferença observável e faz revisão independente.
7. **Evidence Analyst** exige evidência e passos reproduzíveis.
8. **Report Reviewer** exige CWE, severidade e impacto demonstrado.
9. **Orquestrador** só promove um candidato a `reportable` quando todos os gates passam.

A implementação está em `backend/app/services/review_workflow.py`. Detectores não podem
confirmar seus próprios resultados. "Parece inseguro" nunca é critério suficiente: sem
controle/resultado esperado, diferença material, reprodução e evidência, o item fica
`needs_evidence` ou é `rejected`.

O workflow não remove o limite de escopo. Bug bounty continua exigindo autorização
explícita; capacidades ativas são definidas pela política de cada programa.

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
