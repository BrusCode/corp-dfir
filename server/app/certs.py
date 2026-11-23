"""Certificate metadata analysis (the collector never sends private keys)."""

import re

from app.rules import SEVERITY_SCORE, Finding

ICP_HINT = re.compile(r"(?i)icp-brasil|\bAC\b|autoridade certificadora|serasa|certisign|soluti|valid|safeweb")
UNTRUSTED_ROOT_HINT = re.compile(r"(?i)icp-brasil|banco|sicoob|itau|bradesco|caixa|santander|sefaz|receita")
CPF_IN_SUBJECT = re.compile(r":(\d{11})\b")
# Official ICP-Brasil roots (ITI). Name match is not proof, so they become a low "check the
# fingerprint against ITI's publication" item instead of a high alert.
OFFICIAL_ICP_ROOT = re.compile(
    r"(?i)CN=Autoridade Certificadora Raiz Brasileira v\d+,\s*OU=Instituto Nacional de Tecnologia da Informacao - ITI")
# Password written in a certificate file name (e.g. "POSTO X - Pr123456.pfx", "senha 1234").
PASSWORD_IN_NAME = re.compile(r"(?i)(senha|password|\bpwd\b|\bpass\b|\bpr\d{4,8}\b)")
# Bank API client certificates (mTLS for Pix/boleto APIs), not ICP-Brasil.
BANK_API_ISSUER = re.compile(
    r"(?i)itau|sts-s\d+|bradesco|santander|sicoob|sicredi|banco do brasil|caixa econ|banco inter|btg|c6 bank|cora|stone")


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
            if OFFICIAL_ICP_ROOT.search(subject):
                findings.append(_finding("cert_raiz_icp_conferir", "baixa", text, thumb))
            else:
                findings.append(_finding("cert_raiz_suspeita", "alta", text, thumb))
        return findings

    file_name = (record.get("path") or "").replace("/", "\\").rsplit("\\", 1)[-1]
    if origin == "file" and PASSWORD_IN_NAME.search(file_name):
        findings.append(_finding("cert_senha_no_nome", "alta", f"senha aparente no nome do arquivo | {text}",
                                 thumb or record.get("file_sha256")))

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
    elif BANK_API_ISSUER.search(record.get("issuer") or "") and "icp-brasil" not in (record.get("issuer") or "").lower():
        findings.append(_finding("cert_api_bancaria", "alta", f"certificado de API bancária | {text}", thumb))
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
LIFE_EXPORTED = re.compile(r"(?i)foi exportad|has been exported|was exported")
LIFE_EXPIRING = re.compile(r"(?i)prestes a expirar|about to expire|expirou|has expired")
LIFE_REMOVED = re.compile(r"(?i)foi (removid|exclu[íi]d)|has been (deleted|removed)")
KEY_EXPORT = re.compile(r"(?i)exporta[çc][ãa]o de chave|export of persistent")
KEY_IMPORT = re.compile(r"(?i)importa[çc][ãa]o de chave|import of persistent")
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
            # 5059 says in its body whether the persistent key was exported or imported.
            if KEY_EXPORT.search(detail):
                return [_activity_finding("cert_chave_exportada_evento", "alta", record)]
            if KEY_IMPORT.search(detail):
                return [_activity_finding("cert_chave_importada_evento", "media", record)]
            return [_activity_finding("cert_chave_migracao_evento", "baixa", record)]
        if LIFECYCLE_LOG.search(str(record.get("source") or "")):
            if LIFE_EXPORTED.search(detail):
                return [_activity_finding("cert_exportado_evento", "alta", record)]
            if LIFE_EXPIRING.search(detail):
                return [_activity_finding("cert_expirando", "baixa", record)]
            if LIFE_REMOVED.search(detail):
                return [_activity_finding("cert_removido_evento", "media", record)]
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
