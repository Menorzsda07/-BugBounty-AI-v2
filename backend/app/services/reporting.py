from app.models.schemas import Investigation

def markdown_report(inv: Investigation) -> str:
    lines = [f"# Relatório da investigação {inv.id}", "", f"**Alvo:** {inv.target}", f"**Status:** {inv.status}", "", "## Linha do tempo"]
    lines += [f"- {item}" for item in inv.timeline]
    for finding in inv.findings:
        lines += ["", f"## {finding.title}", f"**Estado:** {finding.state}", f"**Severidade:** {finding.severity}", f"**Confiança:** {finding.confidence}%", f"**Endpoint:** `{finding.endpoint}`", "", "### Resumo", finding.summary, "", "### Resultado observado", finding.observed_result, "", "### Resultado esperado", finding.expected_result, "", "### Impacto", finding.impact, "", "### Correção"]
        lines += [f"- {item}" for item in finding.remediation]
        lines += ["", "### Evidências"]
        lines += [f"- `{ev.filename}` — {ev.description} — SHA-256 `{ev.sha256 or 'n/a'}`" for ev in finding.evidence]
    lines += ["", "---", "Revisão humana obrigatória antes de qualquer submissão."]
    return "\n".join(lines)
