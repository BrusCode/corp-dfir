"""Optional LLM triage (OpenAI-compatible, e.g. OpenRouter). Only masked text is sent."""

import json

import httpx

from app import db
from app.config import Settings
from app.rules import Rule, mask_secrets

LABELS = {"benigno", "suspeito", "fraude_provavel"}
PROMPT = (
    "Você é analista de resposta a incidentes de uma empresa de software para postos de "
    "combustível. Um achado automático foi encontrado em conversas de agentes de IA, logs "
    "de acesso remoto ou certificados de um PC da empresa. Segredos já estão mascarados. "
    "Classifique o achado como 'benigno', 'suspeito' ou 'fraude_provavel' considerando o "
    "contexto, e justifique em até 3 frases em português. "
    "Responda SOMENTE JSON: {\"label\": ..., \"reason\": ...}."
)


def enabled(settings: Settings) -> bool:
    return bool(settings.llm_base_url and settings.llm_model)


def _is_openrouter(settings: Settings) -> bool:
    return "openrouter.ai" in settings.llm_base_url


def chat(settings: Settings, user_content: str, *, system: str = PROMPT,
         client: httpx.Client | None = None) -> str:
    body = {
        "model": settings.llm_model,
        "temperature": 0,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user_content}],
    }
    headers = {}
    if settings.llm_api_key:
        headers["Authorization"] = f"Bearer {settings.llm_api_key}"
    if _is_openrouter(settings):
        # Only route to providers that neither store nor train on the prompts.
        body["provider"] = {"data_collection": "deny"}
        headers["X-Title"] = "Corp-DFIR"
    own = client is None
    client = client or httpx.Client(timeout=120)
    try:
        resp = client.post(f"{settings.llm_base_url}/chat/completions", json=body, headers=headers)
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
    finally:
        if own:
            client.close()


def test_connection(settings: Settings) -> tuple[bool, str]:
    if not enabled(settings):
        return False, "Triagem por IA não configurada (informe URL e modelo)."
    if _is_openrouter(settings) and not settings.llm_api_key:
        return False, "Chave da OpenRouter não configurada."
    try:
        answer = chat(settings, "Responda apenas: ok", system="Você responde de forma curta.")
        return True, f"Conectado ao modelo {settings.llm_model}. Resposta: {answer[:80]}"
    except httpx.HTTPStatusError as exc:
        return False, f"Erro HTTP {exc.response.status_code}: {exc.response.text[:200]}"
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        return False, f"Falha: {type(exc).__name__}"


def triage_finding(settings: Settings, finding: dict, rules: list[Rule],
                   client: httpx.Client | None = None) -> tuple[str, str] | None:
    if not enabled(settings) or finding["score"] < settings.llm_min_score:
        return None
    context = db.event_context(settings, finding["event_id"]) if finding.get("event_id") else []
    transcript = "\n".join(
        f"[{e.get('role') or e.get('source')}] {mask_secrets(e['text'][:2000], rules)}"
        for e in context
    )
    content = (
        f"Regra: {finding['rule_id']} ({finding['category']}, {finding['severity']})\n"
        f"Host: {finding['host']} | Perfil: {finding['profile']} | Fonte: {finding['source']}\n"
        f"Trecho: {finding['snippet']}\n\nContexto:\n{transcript[:12000]}"
    )
    system = PROMPT
    if settings.company_context:
        system += "\n\nContexto da empresa (use para separar o rotineiro do anômalo):\n" + settings.company_context[:3000]
    try:
        answer = chat(settings, content, system=system, client=client)
        start, end = answer.find("{"), answer.rfind("}")
        parsed = json.loads(answer[start : end + 1])
        label = parsed.get("label") if parsed.get("label") in LABELS else "suspeito"
        return label, str(parsed.get("reason", ""))[:1000]
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        return "erro", f"falha na triagem: {type(exc).__name__}"
