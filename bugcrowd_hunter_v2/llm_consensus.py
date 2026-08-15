import json, os, sys
from typing import Any, Dict, List

try:
    from openai import OpenAI
except Exception:
    OpenAI = None

PREFERRED = ["gpt-5.1", "gpt-5", "gpt-5-mini"]

SYSTEM = """You are a security bug-bounty review agent. You receive already-collected, redacted evidence from an explicitly authorized Bugcrowd target. Do not invent facts, targets, credentials, impact, or reproduction steps not supported by evidence. Your job is to classify whether the evidence is likely: validated vulnerability, promising candidate needing one minimal validation step, informational, or false positive. Prefer the smallest non-destructive next test. Return strict JSON with keys verdict, confidence, likely_class, impact_reasoning, false_positive_risks, next_minimal_test, reportability."""


def available_models(client: Any) -> List[str]:
    try:
        return [m.id for m in client.models.list().data]
    except Exception:
        return []


def choose_models(ids: List[str]) -> List[str]:
    chosen = [m for m in PREFERRED if m in ids]
    if len(chosen) >= 2:
        return chosen[:2]
    # Fall back to GPT-family models actually available to the account.
    extras = [m for m in ids if m.startswith("gpt-") and "audio" not in m and "realtime" not in m and "image" not in m]
    for m in extras:
        if m not in chosen:
            chosen.append(m)
        if len(chosen) >= 2:
            break
    return chosen


def call(client: Any, model: str, candidate: Dict[str, Any], prior: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    payload = {"candidate": candidate}
    if prior is not None:
        payload["independent_reviews"] = prior
    resp = client.responses.create(
        model=model,
        store=False,
        input=[
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)[:50000]},
        ],
    )
    text = resp.output_text.strip()
    try:
        return json.loads(text)
    except Exception:
        return {"verdict": "parse_error", "raw": text[:5000]}


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: llm_consensus.py candidates.json output.json")
    src, dst = sys.argv[1], sys.argv[2]
    candidates = json.load(open(src, encoding="utf-8"))
    if isinstance(candidates, dict):
        candidates = candidates.get("candidates", candidates.get("findings", []))
    if not isinstance(candidates, list):
        raise SystemExit("candidate input must be a list")

    if not os.getenv("OPENAI_API_KEY") or OpenAI is None:
        json.dump({"enabled": False, "reason": "OPENAI_API_KEY or SDK unavailable", "reviews": []}, open(dst, "w", encoding="utf-8"), indent=2)
        return

    client = OpenAI()
    ids = available_models(client)
    models = choose_models(ids)
    if not models:
        json.dump({"enabled": False, "reason": "no compatible GPT model available", "reviews": []}, open(dst, "w", encoding="utf-8"), indent=2)
        return

    reviewers = models[:2]
    judge = reviewers[0]
    results = []
    for candidate in candidates[:100]:
        independent = []
        for model in reviewers:
            independent.append({"model": model, "review": call(client, model, candidate)})
        merged = call(client, judge, candidate, independent)
        results.append({"fingerprint": candidate.get("fingerprint"), "reviewers": independent, "judge_model": judge, "consensus": merged})

    json.dump({"enabled": True, "models": reviewers, "judge": judge, "reviews": results}, open(dst, "w", encoding="utf-8"), indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
