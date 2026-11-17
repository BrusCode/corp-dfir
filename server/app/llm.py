"""Optional LLM triage. Receives only masked text; disabled without LLM_BASE_URL."""

import json

import httpx

from app import db
from app.config import Settings
from app.rules import Rule, mask_secrets

LABELS = {"benigno", "suspeito", "fraude_provavel"}
PROMPT = (
    "Você é analista de resposta a incidentes de uma empresa de software para postos de "
    "combustível. Um achado automático foi encontrado em conversas de agentes de IA ou logs "
    "de acesso remoto de um PC da empresa. Segredos já estão mascarados. Classifique o achado "
    "como 'benigno', 'suspeito' ou 'fraude_provavel' considerando o contexto, e justifique em "
    "até 3 frases em português. Responda SOMENTE JSON: {\"label\": ..., \"reason\": ...}."
)


def enabled(settings: Settings) -> bool:
    return bool(settings.llm_base_url and settings.llm_model)


def triage_finding(settings: Settings, finding: dict, rules: list[Rule],
                   client: httpx.Client | None = None) -> tuple[str, str] | None:
    if not enabled(settings) or finding["score"] < settings.llm_min_score:
        return None
    context = db.event_context(settings, finding["event_id"])
    transcript = "\n".join(
        f"[{e.get('role') or e.get('source')}] {mask_secrets(e['text'][:2000], rules)}"
        for e in context
    )
    body = {
        "model": settings.llm_model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": PROMPT},
            {"role": "user", "content": (
                f"Regra: {finding['rule_id']} ({finding['category']}, {finding['severity']})\n"
                f"Host: {finding['host']} | Perfil: {finding['profile']} | Fonte: {finding['source']}\n"
                f"Trecho: {finding['snippet']}\n\nContexto:\n{transcript[:12000]}")},
        ],
    }
    headers = {"Authorization": f"Bearer {settings.llm_api_key}"} if settings.llm_api_key else {}
    own = client is None
    client = client or httpx.Client(timeout=120)
    try:
        resp = client.post(f"{settings.llm_base_url}/chat/completions", json=body, headers=headers)
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        start, end = content.find("{"), content.rfind("}")
        parsed = json.loads(content[start : end + 1])
        label = parsed.get("label") if parsed.get("label") in LABELS else "suspeito"
        return label, str(parsed.get("reason", ""))[:1000]
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        return "erro", f"falha na triagem: {type(exc).__name__}"
    finally:
        if own:
            client.close()
