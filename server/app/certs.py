"""Certificate metadata analysis (the collector never sends private keys)."""

import re

from app.rules import SEVERITY_SCORE, Finding

ICP_HINT = re.compile(r"(?i)icp-brasil|\bAC\b|autoridade certificadora|serasa|certisign|soluti|valid|safeweb")
UNTRUSTED_ROOT_HINT = re.compile(r"(?i)icp-brasil|banco|sicoob|itau|bradesco|caixa|santander|sefaz|receita")
CPF_IN_SUBJECT = re.compile(r":(\d{11})\b")


def _finding(rule_id: str, severity: str, snippet: str, thumbprint: str | None) -> Finding:
    return Finding(rule_id=rule_id, category="certificado", severity=severity,
                   score=SEVERITY_SCORE[severity], snippet=snippet,
                   masked=None, fingerprint=(thumbprint or "").upper() or None)


def describe(record: dict) -> str:
    parts = [record.get("subject") or "(não legível)"]
    if record.get("cnpj"):
        parts.append(f"CNPJ {record['cnpj']}")
    if record.get("issuer"):
        parts.append(f"emissor {record['issuer']}")
    if record.get("not_after"):
        parts.append(f"válido até {record['not_after'][:10]}")
    parts.append("com chave privada" if record.get("has_private_key") else "sem chave privada")
    parts.append(f"origem {record.get('origin')}")
    if record.get("path"):
        parts.append(record["path"])
    return " | ".join(parts)


def analyze_cert(record: dict, own_cnpjs: set[str]) -> list[Finding]:
    thumb = record.get("thumbprint")
    origin = record.get("origin") or ""
    text = describe(record)
    findings: list[Finding] = []

    if origin.startswith("store:") and ("Root" in origin or "\\CA" in origin):
        # Trusted roots: alert only on roots that imitate ICP/banks (MITM like the PIX scam).
        subject = record.get("subject") or ""
        if UNTRUSTED_ROOT_HINT.search(subject) and record.get("subject") == record.get("issuer"):
            findings.append(_finding("cert_raiz_suspeita", "alta", text, thumb))
        return findings

    if not record.get("readable"):
        if record.get("extension") in (".pfx", ".p12", ".key"):
            findings.append(_finding("cert_pfx_protegido", "alta", text, record.get("file_sha256")))
        return findings

    cnpj = record.get("cnpj")
    if cnpj:
        if cnpj in own_cnpjs:
            findings.append(_finding("cert_proprio", "baixa", text, thumb))
        else:
            severity = "alta" if record.get("has_private_key") else "media"
            findings.append(_finding("cert_terceiro", severity, text, thumb))
    elif ICP_HINT.search(record.get("issuer") or "") and record.get("has_private_key"):
        findings.append(_finding("cert_icp_sem_cnpj", "media", text, thumb))

    if record.get("host_url") or record.get("referrer_url") or (record.get("zone_id") or 0) >= 3:
        origin_text = f"baixado de {record.get('host_url') or '?'} (referência {record.get('referrer_url') or '?'}) | {text}"
        findings.append(_finding("cert_baixado", "alta", origin_text, thumb))
    return findings
