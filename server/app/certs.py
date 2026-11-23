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


# --- Certificate activity (when/how certificates were used, moved or deleted) -----------
EXPORT_CMD = re.compile(r"(?i)export-pfxcertificate|certutil[^\n]*-exportpfx|\.export\(|pfx[^\n]*export")
IMPORT_CMD = re.compile(r"(?i)import-pfxcertificate|certutil[^\n]*-importpfx|import-certificate|certutil[^\n]*-addstore")
LIFECYCLE_LOG = re.compile(r"(?i)certificateservicesclient-lifecycle")
KEY_MIGRATION_EVENTS = {5059}
KEY_FILE_EVENTS = {5058, 5061}


def _activity_finding(rule_id: str, severity: str, record: dict) -> Finding:
    snippet = " | ".join(str(x) for x in (
        record.get("type"), record.get("source"), record.get("file_name") or record.get("path"),
        record.get("detail")) if x)
    return Finding(rule_id=rule_id, category="certificado", severity=severity,
                   score=SEVERITY_SCORE[severity], snippet=snippet[:600],
                   masked=None, fingerprint=None)


def analyze_activity(record: dict) -> list[Finding]:
    kind = record.get("type")
    detail = str(record.get("detail") or "")
    if kind == "lnk_aberto":
        return [_activity_finding("cert_arquivo_aberto", "media", record)]
    if kind == "historico_comando":
        if EXPORT_CMD.search(detail):
            return [_activity_finding("cert_exportado", "alta", record)]
        if IMPORT_CMD.search(detail):
            return [_activity_finding("cert_importado", "media", record)]
        return [_activity_finding("cert_comando", "baixa", record)]
    if kind == "acesso_remoto_arquivo":
        return [_activity_finding("cert_transferido_remoto", "alta", record)]
    if kind == "cert_na_lixeira":
        return [_activity_finding("cert_apagado", "alta", record)]
    if kind == "evento_windows":
        event_id = record.get("event_id")
        if event_id in KEY_MIGRATION_EVENTS:
            return [_activity_finding("cert_chave_exportada_evento", "alta", record)]
        if LIFECYCLE_LOG.search(str(record.get("source") or "")):
            return [_activity_finding("cert_instalado_evento", "media", record)]
        if event_id in KEY_FILE_EVENTS:
            return [_activity_finding("cert_chave_acessada_evento", "baixa", record)]
        return [_activity_finding("cert_evento", "baixa", record)]
    if kind == "execucao_ferramenta":
        return [_activity_finding("cert_ferramenta_executada", "baixa", record)]
    if kind == "chave_privada_criada":
        return [_activity_finding("cert_chave_privada_criada", "baixa", record)]
    return []


def describe_activity(record: dict) -> str:
    return " | ".join(str(x) for x in (
        record.get("type"), record.get("source"), record.get("file_name"), record.get("path"),
        record.get("detail")) if x)[:4000]
