"""Collector scripts served to the panel (read from the repository's collector/ folder)."""

import hashlib
import re
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

VERSION = re.compile(r'^\$(?:CollectorVersion|Version)\s*=\s*"([^"]+)"', re.M)
SYNOPSIS = re.compile(r"\.SYNOPSIS\s*\n(.*?)(?:\n\s*\n|\n\s*\.[A-Z]|#>)", re.S)

# Suggested argument variants per script (appended to the base connection arguments).
VARIANTS = {
    "Invoke-DfirCollect.ps1": [
        ("Coleta completa", ""),
        ("Sem conversas de IA", "-SemIA"),
        ("Complementar ao script de certificados (sem IA e sem certificados)", "-SemIA -SemCertificados"),
        ("Só testar conexão", "-TestConnection"),
    ],
    "Invoke-DfirCertCollect.ps1": [
        ("Coleta de certificados", ""),
        ("Só testar conexão", "-TestConnection"),
    ],
    "Invoke-DfirCertQuarantine.ps1": [
        ("Relatório (não altera nada)", ""),
        ("Quarentena de arquivos", "-Modo Quarentena"),
        ("Quarentena + remover instalados (rodar como usuário logado)", "-Modo Quarentena -RemoverInstalados"),
    ],
}


@dataclass
class Script:
    name: str
    version: str
    synopsis: str
    sha256: str
    size: int
    modified: str
    variants: list[tuple[str, str]]


def list_scripts(directory: Path) -> list[Script]:
    if not directory.is_dir():
        return []
    scripts = []
    for path in sorted(directory.glob("*.ps1")):
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        version = VERSION.search(text)
        synopsis = SYNOPSIS.search(text)
        scripts.append(Script(
            name=path.name,
            version=version.group(1) if version else "",
            synopsis=" ".join(line.strip() for line in synopsis.group(1).splitlines()).strip() if synopsis else "",
            sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            size=path.stat().st_size,
            modified=datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            variants=VARIANTS.get(path.name, [("Padrão", "")]),
        ))
    return scripts


def get_script_path(directory: Path, name: str) -> Path | None:
    """Only names listed in the folder are served (no path traversal)."""
    for script in list_scripts(directory):
        if script.name == name:
            return directory / script.name
    return None


def server_thumbprint(cert_path: Path) -> str:
    """SHA-1 thumbprint as Windows shows it (used by -CertThumbprint)."""
    try:
        der = ssl.PEM_cert_to_DER_cert(cert_path.read_text())
    except (OSError, ValueError):
        return ""
    return hashlib.sha1(der).hexdigest().upper()
