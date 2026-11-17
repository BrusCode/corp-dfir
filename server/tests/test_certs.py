import json
import zipfile

from app import db
from app.certs import analyze_cert
from app.pipeline import process_bundle
from tests.conftest import make_bundle

OWN = {"11222333000181"}


def rec(**kw):
    base = {"origin": "file", "profile": "joao", "path": r"C:\Users\joao\Downloads\a.pfx",
            "readable": True, "thumbprint": "AB" * 20,
            "subject": "CN=COMERCIAL DE COMBUSTIVEIS BONANZA LTDA:07999649000107",
            "issuer": "CN=AC SOLUTI Multipla v5, O=ICP-Brasil", "has_private_key": True,
            "cnpj": "07999649000107", "host_url": None, "referrer_url": None, "zone_id": None,
            "not_after": "2027-05-01T00:00:00Z", "extension": ".pfx"}
    base.update(kw)
    return base


def ids(findings):
    return {f.rule_id for f in findings}


def test_third_party_cnpj_is_high():
    found = analyze_cert(rec(), OWN)
    assert "cert_terceiro" in ids(found)
    assert all(f.severity == "alta" for f in found if f.rule_id == "cert_terceiro")


def test_own_cnpj_is_low():
    found = analyze_cert(rec(cnpj="11222333000181", subject="CN=NOSSA EMPRESA:11222333000181"), OWN)
    assert ids(found) == {"cert_proprio"}


def test_downloaded_cert_flags_origin():
    found = analyze_cert(rec(zone_id=3, host_url="https://webposto.zendesk.com/attachments/x"), OWN)
    origin = next(f for f in found if f.rule_id == "cert_baixado")
    assert origin.severity == "alta"
    assert "zendesk" in origin.snippet


def test_unreadable_pfx_still_reported():
    found = analyze_cert(rec(readable=False, subject=None, cnpj=None, thumbprint=None), OWN)
    assert "cert_pfx_protegido" in ids(found)


def test_icp_without_cnpj_is_medium():
    found = analyze_cert(rec(cnpj=None, subject="CN=FULANO DE TAL:12345678901"), OWN)
    assert "cert_icp_sem_cnpj" in ids(found)


def test_public_root_store_ignored_unless_untrusted_issuer():
    store = rec(origin="store:Cert:\\LocalMachine\\Root", cnpj=None, has_private_key=False,
                subject="CN=Microsoft Root", issuer="CN=Microsoft Root")
    assert analyze_cert(store, OWN) == []
    fake = rec(origin="store:Cert:\\LocalMachine\\Root", cnpj=None, has_private_key=False,
               subject="CN=ICP-Brasil v5 Raiz", issuer="CN=ICP-Brasil v5 Raiz")
    assert "cert_raiz_suspeita" in ids(analyze_cert(fake, OWN))


def test_pipeline_ingests_certs_json_and_correlates_thumbprint(settings, tmp_path, monkeypatch):
    monkeypatch.setenv("DFIR_OWN_CNPJS", "11222333000181")
    from app import config
    config.get_settings.cache_clear()
    for host in ("SUP-1", "SUP-2"):
        folder = tmp_path / host
        folder.mkdir()
        z = make_bundle(folder, host, {"x.txt": ("ia", "nada")})
        with zipfile.ZipFile(z, "a") as zf:
            zf.writestr("certs.json", json.dumps([rec()]))
        cid = db.create_collection(config.get_settings(), host=host, filename=z.name,
                                   sha256="y" * 64, stored_path=str(z), custody={})
        process_bundle(config.get_settings(), cid)
    groups = db.correlated_secrets(config.get_settings())
    cert_group = next(g for g in groups if g["rule_id"] == "cert_terceiro")
    assert cert_group["hosts"] == 2
    assert db.list_certificates(config.get_settings())
