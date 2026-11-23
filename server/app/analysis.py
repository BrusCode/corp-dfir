"""AI analysis of the results (the same data the report exports), stored in the system.

Only masked data goes to the model: snippets and events are already stored masked, and the
digest masks again before sending.
"""

import html
import re
from collections import Counter

import httpx

from app import config, db, llm, reportdata
from app.config import Settings
from app.rules import load_rules, mask_secrets

MAX_DIGEST_CHARS = 24_000
ANALYSIS_PROMPT = (
    "Você é analista sênior de resposta a incidentes de uma empresa de software para postos de "
    "combustível (sistema WebPosto/Retaguarda). Recebe o resultado consolidado de uma coleta "
    "forense em computadores: certificados digitais (instalados e em arquivo, com origem de "
    "download), atividade com certificados, acessos remotos e segredos. Segredos estão mascarados.\n"
    "Escreva em português do Brasil, em Markdown, para a DIRETORIA, com estas seções:\n"
    "## Resumo executivo (5 a 8 linhas, linguagem não técnica)\n"
    "## Principais riscos (priorizados, com o porquê)\n"
    "## Evidências relevantes (cite máquina, arquivo, CNPJ/cliente e datas)\n"
    "## O que os dados não permitem afirmar (limitações)\n"
    "## Recomendações (imediatas e estruturais)\n"
    "## Próximos passos da investigação\n"
    "Regras: separe fatos de hipóteses; não acuse pessoas, descreva comportamentos e riscos; "
    "não invente dados que não estejam no material; use listas curtas."
)


def _section(title: str, lines: list[str], limit: int) -> str:
    if not lines:
        return f"### {title}\n(nenhum)\n"
    extra = f"\n(+{len(lines) - limit} itens omitidos)" if len(lines) > limit else ""
    return f"### {title}\n" + "\n".join(lines[:limit]) + extra + "\n"


def build_digest(settings: Settings, host: str = "") -> tuple[str, dict]:
    host = host or None
    rules = load_rules()
    findings = reportdata.dedupe_findings(db.list_findings(settings, host=host, limit=50_000))
    certs = reportdata.dedupe_certs(db.list_certificates(settings, host))
    activity, omitted = reportdata.focus_timeline(db.list_cert_activity(settings, host, limit=20_000))
    remote = db.remote_events(settings, host)
    collections = [c for c in db.list_collections(settings) if not host or c["host"] == host]
    secrets = [s for s in db.correlated_secrets(settings)
               if not host or host in (s.get("host_list") or "").split(",")]

    by_rule = Counter(f["rule_id"] for f in findings)
    by_sev = Counter(f["severity"] for f in findings)
    triage = Counter(f["triage_label"] or "sem_triagem" for f in findings)
    hosts = sorted({c["host"] for c in collections})
    stats = {"hosts": len(hosts), "collections": len(collections), "findings": len(findings),
             "certificates_flagged": len(certs), "activity": len(activity), "remote_events": len(remote)}

    parts = [
        f"Escopo: {'máquina ' + host if host else 'todas as máquinas'} ({', '.join(hosts) or '-'})",
        f"Coletas: {len(collections)} | Achados: {len(findings)} "
        f"(alta {by_sev.get('alta', 0)}, média {by_sev.get('media', 0)}, baixa {by_sev.get('baixa', 0)})",
        "Achados por regra: " + ", ".join(f"{k}={v}" for k, v in by_rule.most_common()),
        "Triagem automática por achado: " + ", ".join(f"{k}={v}" for k, v in triage.most_common()),
        "",
        _section("Certificados sinalizados (máquina | veredito | titular/CNPJ | chave privada | criado/instalado | origem do download | local)", [
            f"- {c['host']} | {c['verdict']} | {c['subject'] or '(ilegível)'} {c['cnpj'] or ''} | "
            f"{'com chave' if c['has_private_key'] else 'sem chave'} | {(c['file_created'] or '')[:10]} | "
            f"{c['host_url'] or '-'} | {c['path'] or c['origin']}" for c in certs], 120),
        "Eventos de rotina omitidos da linha do tempo: " + (", ".join(f"{k}={v}" for k, v in omitted.most_common()) or "nenhum"),
        _section("Linha do tempo de atividade com certificados (horários UTC)", [
            f"- {(a['ts'] or '')[:16]} | {a['host']} | {a['role']} | {a['rule_ids'] or ''} | {a['text'][:220]}"
            for a in activity], 120),
        _section("Acessos remotos (linhas de log)", [
            f"- {r['host']} | {r['source']} | {r['text'][:200]}" for r in remote], 60),
        _section("Segredos correlacionados entre máquinas (mascarados)", [
            f"- {s['rule_id']} {s['masked']} | máquinas: {s['host_list']} | ocorrências {s['occurrences']}"
            for s in secrets], 40),
        _section("Outros achados relevantes (segredos e indícios de fraude)", [
            f"- {f['host']} | {f['rule_id']} ({f['severity']}) | {f['snippet'][:220]}"
            for f in findings if f["category"] in ("segredo", "fraude")], 60),
        _section("Coletas e custódia", [
            f"- {c['host']} | {c['filename']} | recebido {c['received_at'][:19]} | {c['status']} | sha256 {c['sha256'][:16]}…"
            for c in collections], 40),
    ]
    digest = mask_secrets("\n".join(parts), rules)
    if len(digest) > MAX_DIGEST_CHARS:
        digest = digest[:MAX_DIGEST_CHARS] + "\n(conteúdo truncado por tamanho)"
    return digest, stats


def run_analysis(settings: Settings, analysis_id: int) -> None:
    record = db.get_analysis(settings, analysis_id)
    if record is None:
        return
    eff = config.effective(settings)
    if not llm.enabled(eff):
        db.fail_analysis(settings, analysis_id, "IA não configurada (Configurações: URL e modelo).")
        return
    try:
        digest, stats = build_digest(settings, record["scope_host"])
        system = ANALYSIS_PROMPT
        if eff.company_context:
            system += "\n\nContexto da empresa:\n" + eff.company_context[:3000]
        with httpx.Client(timeout=300) as http:
            text = llm.chat(eff, digest, system=system, client=http)
        db.finish_analysis(settings, analysis_id, text=text.strip(), model=eff.llm_model, stats=stats)
    except Exception as exc:  # recorded for the user; the worker must not crash
        db.fail_analysis(settings, analysis_id, f"{type(exc).__name__}: {exc}")


_BOLD = re.compile(r"\*\*(.+?)\*\*")
_CODE = re.compile(r"`([^`]+)`")


def _inline(text: str) -> str:
    text = html.escape(text)
    text = _BOLD.sub(r"<strong>\1</strong>", text)
    return _CODE.sub(r"<code>\1</code>", text)


def render_markdown(text: str) -> str:
    """Small, safe Markdown subset (headings, lists, bold, code, paragraphs); escapes all HTML."""
    out: list[str] = []
    list_tag = None
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        bullet = re.match(r"^\s*[-*]\s+(.*)", line)
        number = re.match(r"^\s*\d+[.)]\s+(.*)", line)
        tag = "ul" if bullet else "ol" if number else None
        if list_tag and tag != list_tag:
            out.append(f"</{list_tag}>")
            list_tag = None
        if tag:
            if not list_tag:
                out.append(f"<{tag}>")
                list_tag = tag
            out.append(f"<li>{_inline((bullet or number).group(1))}</li>")
            continue
        heading = re.match(r"^(#{1,4})\s+(.*)", line)
        if heading:
            level = min(len(heading.group(1)) + 2, 5)
            out.append(f"<h{level}>{_inline(heading.group(2))}</h{level}>")
        elif line.strip():
            out.append(f"<p>{_inline(line)}</p>")
    if list_tag:
        out.append(f"</{list_tag}>")
    return "\n".join(out)
