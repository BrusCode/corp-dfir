import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from app import analysis, config, db, llm, main
from app.certs import analyze_cert
from app.pipeline import process_bundle
from tests.conftest import make_bundle

KEY = "sk-or-v1-" + "f9" * 32
ORIGIN = {"Origin": "https://testserver"}


def rec(**kw):
    base = {"origin": "file", "profile": "keslley", "path": r"C:\Users\k\Downloads\x.pfx",
            "readable": True, "thumbprint": "AB" * 20, "subject": "CN=POSTO X LTDA:27656438000189",
            "issuer": "CN=AC SOLUTI Multipla v5, O=ICP-Brasil", "has_private_key": True,
            "cnpj": "27656438000189", "extension": ".pfx", "file_created": "2026-11-16T11:20:47Z"}
    base.update(kw)
    return base


def ids(found):
    return {f.rule_id for f in found}


# --- regras novas -------------------------------------------------------------------------
def test_password_in_filename_even_when_unreadable():
    for name in ("DIRCEU FLAP - Pr123456.pfx", "posto senha 1234.pfx", "cert_password.p12"):
        found = analyze_cert(rec(path=rf"C:\Users\k\Downloads\{name}", readable=False, subject=None,
                                 cnpj=None, thumbprint=None, file_sha256="aa" * 32), set())
        assert "cert_senha_no_nome" in ids(found), name
    clean = analyze_cert(rec(path=r"C:\Users\k\Downloads\ARARA AZUL_07675128000102.pfx"), set())
    assert "cert_senha_no_nome" not in ids(clean)


def test_bank_api_certificate():
    found = analyze_cert(rec(extension=".crt", has_private_key=False, cnpj=None,
                             subject="OU=Cliente, OU=POSTO SHOPPING LTDA, CN=e7293f02-0ca0-4181-b3d8-91b7ca8fa92f",
                             issuer="CN=STS-S0654, OU=Itau Unibanco S.A., O=Itau Unibanco S.A."), set())
    assert next(f for f in found if f.rule_id == "cert_api_bancaria").severity == "alta"


def test_official_icp_roots_are_not_suspicious():
    for v in ("v5", "v10"):
        subject = (f"CN=Autoridade Certificadora Raiz Brasileira {v}, OU=Instituto Nacional de "
                   "Tecnologia da Informacao - ITI, O=ICP-Brasil, C=BR")
        found = analyze_cert(rec(origin="store:Cert:\\LocalMachine\\Root", subject=subject,
                                 issuer=subject, cnpj=None, has_private_key=False), set())
        assert ids(found) == {"cert_raiz_icp_conferir"}
        assert all(f.severity == "baixa" for f in found)


# --- linha do tempo a partir do inventário ------------------------------------------------
def test_timeline_built_from_inventory_when_no_activity_file(settings, tmp_path):
    z = make_bundle(tmp_path, "PC-INV", {})
    with zipfile.ZipFile(z, "a") as zf:
        zf.writestr("certs.json", json.dumps([
            rec(origin="store:CurrentUser\\My", path=r"C:\Users\k\AppData\...\ABC"),
            rec(host_url="https://web.whatsapp.com/", file_created="2026-11-05T19:07:10Z"),
        ]))
    cid = db.create_collection(config.get_settings(), host="PC-INV", filename=z.name,
                               sha256="i" * 64, stored_path=str(z), custody={})
    process_bundle(config.get_settings(), cid)
    timeline = db.list_cert_activity(config.get_settings(), host="PC-INV")
    kinds = [t["role"] for t in timeline]
    assert kinds == ["arquivo_certificado", "certificado_instalado"]
    assert "web.whatsapp.com" in timeline[0]["text"]


# --- contexto da empresa e análise por IA -------------------------------------------------
@pytest.fixture
def client(settings, monkeypatch):
    monkeypatch.setattr(main, "enqueue", lambda cid: None)
    monkeypatch.setattr(main, "enqueue_analysis", lambda aid: None)
    return TestClient(main.app)


def _seed(settings, tmp_path, host="KESLLEY-NOTEBOO"):
    z = make_bundle(tmp_path, host, {".env": ("segredo", f"OPENROUTER_API_KEY={KEY}")})
    with zipfile.ZipFile(z, "a") as zf:
        zf.writestr("certs.json", json.dumps([
            rec(path=r"C:\Users\k\Downloads\AUTO POSTO ILHA - Pr123456.pfx", readable=False,
                subject=None, cnpj=None, thumbprint=None, file_sha256="bb" * 32),
            rec(origin="store:CurrentUser\\My", subject="CN=VIA PETROLEO LTDA:39688883000100",
                cnpj="39688883000100"),
        ]))
    cid = db.create_collection(config.get_settings(), host=host, filename=z.name,
                               sha256=host[:1] * 64, stored_path=str(z), custody={"hostname": host})
    process_bundle(config.get_settings(), cid)


def test_company_context_saved_and_sent_to_triage(client, settings, monkeypatch):
    client.post("/admin", headers=ORIGIN, data={"own_cnpjs": "", "llm_min_score": "5",
                                                "company_context": "Suporte configura certificados de clientes."})
    eff = config.effective(settings)
    assert eff.company_context == "Suporte configura certificados de clientes."
    seen = {}
    monkeypatch.setattr(llm, "chat", lambda s, content, **kw: seen.setdefault("system", kw.get("system")) or '{"label":"benigno","reason":"ok"}')
    db.set_setting(settings, "llm_base_url", "https://x/api/v1")
    db.set_setting(settings, "llm_model", "m")
    llm.triage_finding(config.effective(settings),
                       {"score": 5, "event_id": None, "rule_id": "r", "category": "c", "severity": "alta",
                        "host": "h", "profile": "p", "source": "s", "snippet": "x"}, [])
    assert "Suporte configura certificados de clientes." in seen["system"]


def test_digest_is_masked_and_summarizes(settings, tmp_path):
    _seed(settings, tmp_path)
    digest, stats = analysis.build_digest(config.get_settings(), "KESLLEY-NOTEBOO")
    assert KEY not in digest
    assert "cert_senha_no_nome" in digest and "VIA PETROLEO" in digest
    assert stats["findings"] >= 3 and stats["hosts"] == 1


def test_analysis_runs_and_is_stored(client, settings, tmp_path, monkeypatch):
    _seed(settings, tmp_path)
    db.set_setting(settings, "llm_base_url", "https://x/api/v1")
    db.set_setting(settings, "llm_model", "modelo-x")
    monkeypatch.setattr(llm, "chat", lambda s, content, **kw: "## Resumo\n- Exposição de **PFX** com senha no nome.")
    r = client.post("/report/analyze", headers=ORIGIN, data={"host": "KESLLEY-NOTEBOO"}, follow_redirects=False)
    assert r.status_code == 303
    aid = db.list_analyses(settings, "KESLLEY-NOTEBOO")[0]["id"]
    analysis.run_analysis(config.get_settings(), aid)
    done = db.get_analysis(settings, aid)
    assert done["status"] == "concluida" and "PFX" in done["text"] and done["model"] == "modelo-x"


def test_analysis_without_llm_fails_gracefully(settings, tmp_path):
    _seed(settings, tmp_path)
    aid = db.create_analysis(settings, "KESLLEY-NOTEBOO")
    analysis.run_analysis(config.get_settings(), aid)
    a = db.get_analysis(settings, aid)
    assert a["status"] == "erro" and "configurada" in a["error"]


# --- relatório ------------------------------------------------------------------------------
def test_report_html_with_analysis(client, settings, tmp_path, monkeypatch):
    _seed(settings, tmp_path)
    aid = db.create_analysis(settings, "KESLLEY-NOTEBOO")
    db.finish_analysis(settings, aid, text="## Resumo\n- Item **importante** <script>x</script>",
                       model="m", stats={"findings": 3})
    page = client.get("/report?host=KESLLEY-NOTEBOO")
    assert page.status_code == 200
    html = page.text
    for expected in ("Relatório", "KESLLEY-NOTEBOO", "Análise dos resultados", "<strong>importante</strong>",
                     "VIA PETROLEO", "cert_senha_no_nome", "Cadeia de custódia"):
        assert expected in html, expected
    assert "<script>x</script>" not in html
    assert KEY not in html
    dl = client.get("/report/download?host=KESLLEY-NOTEBOO")
    assert dl.status_code == 200 and "attachment" in dl.headers["content-disposition"]
    assert ".html" in dl.headers["content-disposition"]


def test_report_all_hosts(client, settings, tmp_path):
    _seed(settings, tmp_path)
    assert client.get("/report").status_code == 200
