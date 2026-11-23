"""Shared shaping of results for the report and the AI analysis (same data in both)."""

from collections import Counter

# Timeline types always shown; other events only when they produced a medium/high finding.
KEY_TIMELINE_TYPES = {"arquivo_certificado", "certificado_instalado", "lnk_aberto", "historico_comando",
                      "acesso_remoto_arquivo", "cert_na_lixeira"}


def dedupe_certs(certs: list[dict]) -> list[dict]:
    """The same certificate appears once per collection; keep the most recent collection's row."""
    seen, out = set(), []
    for c in sorted(certs, key=lambda c: -(c.get("collection_id") or 0)):
        key = (c["host"], c.get("thumbprint") or c.get("file_sha256") or "", c.get("path") or c.get("origin"))
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


def dedupe_findings(findings: list[dict]) -> list[dict]:
    seen, out = set(), []
    for f in sorted(findings, key=lambda f: -(f.get("collection_id") or 0)):
        key = (f["host"], f["rule_id"], f.get("fingerprint") or "", f.get("original_path") or "",
               (f.get("snippet") or "")[:200] if not f.get("fingerprint") else "")
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def focus_timeline(activity: list[dict]) -> tuple[list[dict], Counter]:
    """Drop duplicates across collections and routine low-severity events (counted, not listed)."""
    seen, kept, omitted = set(), [], Counter()
    for a in activity:
        key = (a["host"], a.get("role"), a.get("ts"), (a.get("text") or "")[:200])
        if key in seen:
            continue
        seen.add(key)
        if a.get("role") in KEY_TIMELINE_TYPES or (a.get("score") or 0) >= 3:
            kept.append(a)
        else:
            omitted[a.get("rule_ids") or a.get("role") or "outros"] += 1
    return kept, omitted
