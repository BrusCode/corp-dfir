import hashlib
import ssl
import subprocess

import pytest
from fastapi.testclient import TestClient

from app import config, main

SCRIPT = '''<#
.SYNOPSIS
  Corp-DFIR — coleta de teste.
  Segunda linha.
#>
param([string]$Server)
$CollectorVersion = "9.9.9"
'''


@pytest.fixture
def client(settings, tmp_path, monkeypatch):
    sdir = tmp_path / "collector"
    sdir.mkdir()
    (sdir / "Invoke-DfirCollect.ps1").write_text(SCRIPT, encoding="utf-8")
    (sdir / "Invoke-DfirCertQuarantine.ps1").write_text(SCRIPT.replace('$CollectorVersion = "9.9.9"', '$Version = "quarentena-1.0.0"'), encoding="utf-8")
    (sdir / "notas.txt").write_text("ignorar", encoding="utf-8")
    crt = tmp_path / "server.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(tmp_path / "k"),
                    "-out", str(crt), "-days", "1", "-subj", "/CN=t"], check=True, capture_output=True)
    monkeypatch.setenv("DFIR_SCRIPTS_DIR", str(sdir))
    monkeypatch.setenv("DFIR_SERVER_CERT", str(crt))
    config.get_settings.cache_clear()
    c = TestClient(main.app, base_url="https://192.168.10.56:8444")
    c.crt = crt
    c.sdir = sdir
    return c


def test_scripts_page_lists_versions_and_prefilled_arguments(client):
    page = client.get("/scripts").text
    der = ssl.PEM_cert_to_DER_cert(client.crt.read_text())
    thumb = hashlib.sha1(der).hexdigest().upper()
    assert "Invoke-DfirCollect.ps1" in page and "9.9.9" in page and "quarentena-1.0.0" in page
    assert "coleta de teste" in page
    assert "-Server 192.168.10.56 -Port 8444 -Token test-token" in page
    assert thumb in page
    assert "-SemIA" in page and "-Modo Quarentena" in page and "-TestConnection" in page
    assert "notas.txt" not in page


def test_raw_and_download(client):
    raw = client.get("/scripts/Invoke-DfirCollect.ps1/raw")
    assert raw.status_code == 200 and "$CollectorVersion" in raw.text
    dl = client.get("/scripts/Invoke-DfirCollect.ps1/raw?download=1")
    assert "attachment" in dl.headers["content-disposition"]


def test_unknown_or_traversal_rejected(client):
    assert client.get("/scripts/notas.txt/raw").status_code == 404
    assert client.get("/scripts/..%2F..%2Fetc%2Fpasswd/raw").status_code == 404
