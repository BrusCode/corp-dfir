import hashlib
import json
import zipfile

from fastapi.testclient import TestClient

from app import config, db, main, parsers
from app.certs import analyze_activity
from app.pipeline import process_bundle
from app.timefmt import br_datetime

ORIGIN = {"Origin": "https://testserver"}


# --- leitura de logs de acesso remoto ------------------------------------------------------
def test_utf16_teamviewer_log_is_parsed(tmp_path):
    p = tmp_path / "TeamViewer15_Logfile.log"
    p.write_bytes("2026/11/05 15:10:00 CarrierInfo: incoming connection from 1234567890\r\n".encode("utf-16"))
    events = parsers.parse_file(p, "acesso_remoto")
    assert events and "1234567890" in events[0].text


def test_utf16_without_bom(tmp_path):
    p = tmp_path / "Connections_incoming.txt"
    p.write_bytes("1234567890\tJOAO-PC\t05-11-2026 15:10:00\r\n".encode("utf-16-le"))
    assert "JOAO-PC" in parsers.parse_file(p, "acesso_remoto")[0].text


def test_large_remote_log_not_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(parsers, "MAX_TEXT_BYTES", 10)
    p = tmp_path / "ad.trace"
    p.write_text("info 2026-11-05 15:11:00 Incoming session request from 1.2.3.4\n" * 3)
    assert len(parsers.parse_file(p, "acesso_remoto")) == 3


def test_skip_reason(tmp_path, monkeypatch):
    b = tmp_path / "x.bin"
    b.write_bytes(b"\x00\x01\x02" * 10)
    assert parsers.skip_reason(b, "ia") == "binário"
    u = tmp_path / "x.dat"
    u.write_text("texto")
    assert parsers.skip_reason(u, "ia") == "formato não suportado"
    monkeypatch.setattr(parsers, "MAX_TEXT_BYTES", 2)
    t = tmp_path / "x.txt"
    t.write_text("abcdef")
    assert parsers.skip_reason(t, "segredo") == "acima do limite de leitura"


# --- classificação de eventos de certificado ------------------------------------------------
def act(**kw):
    base = {"type": "evento_windows", "source": "Security", "ts": "2026-11-23T19:05:00Z"}
    base.update(kw)
    return base


def ids(found):
    return {f.rule_id for f in found}


def test_lifecycle_export_is_high_and_expiry_low():
    lifecycle = "Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational"
    exported = analyze_activity(act(source=lifecycle, event_id=1007,
                                    detail='Um certificado foi exportado. Consulte a seção "Detalhes"'))
    assert ids(exported) == {"cert_exportado_evento"} and exported[0].severity == "alta"
    assert ids(analyze_activity(act(source=lifecycle, detail="A certificate has been exported."))) == {"cert_exportado_evento"}
    assert ids(analyze_activity(act(source=lifecycle, detail="Um certificado está prestes a expirar."))) == {"cert_expirando"}
    assert ids(analyze_activity(act(source=lifecycle, detail="Um certificado foi instalado."))) == {"cert_instalado_evento"}


def test_key_migration_export_vs_import():
    exp = analyze_activity(act(event_id=5059, detail="Operação de migração de chave. ... Operação: Exportação de chave criptográfica persistente."))
    assert ids(exp) == {"cert_chave_exportada_evento"} and exp[0].severity == "alta"
    imp = analyze_activity(act(event_id=5059, detail="Key migration operation. Operation: Import of persistent cryptographic key."))
    assert ids(imp) == {"cert_chave_importada_evento"} and imp[0].severity == "media"
    other = analyze_activity(act(event_id=5059, detail="Operação de migração de chave. Assunto: ..."))
    assert ids(other) == {"cert_chave_migracao_evento"} and other[0].severity == "baixa"


# --- horário de Brasília ---------------------------------------------------------------------
def test_br_datetime():
    assert br_datetime("2026-11-23T20:05:49Z") == "23/11/2026 17:05:49"
    assert br_datetime("2026-11-23T20:05:49.4732173Z") == "23/11/2026 17:05:49"
    assert br_datetime("2026-11-23T20:05:49+00:00", seconds=False) == "23/11/2026 17:05"
    assert br_datetime("2026-11-23 20:05:49") == "23/11/2026 17:05:49"
    assert br_datetime(None) == "" and br_datetime("") == ""
    assert br_datetime("lixo") == "lixo"


# --- navegador de arquivos da coleta ----------------------------------------------------------
def bundle(tmp_path):
    z = tmp_path / "CorpDFIR-PC-B.zip"
    env = b"OPENROUTER_API_KEY=sk-or-v1-" + b"c3" * 32
    trace = b"info 2026-11-05 15:11:00 Incoming session request from 203.0.113.9\n"
    files = {"files/k/Users/k/.env": ("segredo", env),
             "files/k/Users/k/AppData/Roaming/AnyDesk/ad.trace": ("acesso_remoto", trace),
             "files/k/Users/k/blob.bin": ("ia", b"\x00\x01\x02")}
    manifest = [{"profile": "k", "category": cat, "original_path": "C:\\" + arc.split("/", 2)[2].replace("/", "\\"),
                 "archive_path": arc, "size": len(data), "mtime": "2026-11-05T18:11:00Z",
                 "sha256": hashlib.sha256(data).hexdigest(), "status": "copied"}
                for arc, (cat, data) in files.items()]
    manifest.append({"profile": "k", "category": "ia", "original_path": r"C:\Users\k\.claude\big.jsonl",
                     "archive_path": None, "size": 999, "sha256": None, "status": "skipped_too_large"})
    with zipfile.ZipFile(z, "w") as zf:
        for arc, (_, data) in files.items():
            zf.writestr(arc, data)
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr("custody.json", json.dumps({"hostname": "PC-B"}))
    cid = db.create_collection(config.get_settings(), host="PC-B", filename=z.name,
                               sha256=hashlib.sha256(z.read_bytes()).hexdigest(),
                               stored_path=str(z), custody={"hostname": "PC-B"})
    process_bundle(config.get_settings(), cid)
    return cid


def test_collection_files_listing_with_event_counts(settings, tmp_path):
    cid = bundle(tmp_path)
    rows = db.list_collection_files(config.get_settings(), cid)
    by_path = {r["original_path"]: r for r in rows}
    assert by_path[r"C:\Users\k\AppData\Roaming\AnyDesk\ad.trace"]["events"] == 1
    assert by_path[r"C:\Users\k\.env"]["findings"] >= 1
    assert by_path[r"C:\Users\k\blob.bin"]["reason"] == "binário"
    assert by_path[r"C:\Users\k\.claude\big.jsonl"]["status"] == "skipped_too_large"
    only_remote = db.list_collection_files(config.get_settings(), cid, category="acesso_remoto")
    assert [r["category"] for r in only_remote] == ["acesso_remoto"]
    assert len(db.list_collection_files(config.get_settings(), cid, q="anydesk")) == 1


def test_collection_pages(settings, tmp_path, monkeypatch):
    monkeypatch.setattr(main, "enqueue", lambda cid: None)
    cid = bundle(tmp_path)
    client = TestClient(main.app)
    page = client.get(f"/collections/{cid}")
    assert page.status_code == 200 and "ad.trace" in page.text and "binário" in page.text
    detail = client.get(f"/collections/{cid}/file", params={"path": r"C:\Users\k\.env"})
    assert detail.status_code == 200
    assert "c3c3c3c3" not in detail.text and "sk-or-" in detail.text
    assert client.get(f"/collections/{cid}/file", params={"path": "C:\\nao\\existe"}).status_code == 404
    assert f'href="/collections/{cid}"' in client.get("/").text


def test_report_deduplicates_certificates_across_collections(settings, tmp_path, monkeypatch):
    monkeypatch.setattr(main, "enqueue", lambda cid: None)
    cert = {"origin": "store:CurrentUser\\My", "profile": "k", "path": r"C:\Users\k\...\ABC",
            "readable": True, "thumbprint": "AB" * 20, "subject": "CN=POSTO Z LTDA:12614598000198",
            "issuer": "CN=AC SOLUTI, O=ICP-Brasil", "has_private_key": True, "cnpj": "12614598000198",
            "file_created": "2026-11-16T17:16:27Z"}
    for n in range(2):
        folder = tmp_path / f"c{n}"
        folder.mkdir()
        z = folder / f"b{n}.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("manifest.json", "[]")
            zf.writestr("certs.json", json.dumps([cert]))
            zf.writestr("custody.json", json.dumps({"hostname": "PC-D"}))
        cid = db.create_collection(config.get_settings(), host="PC-D", filename=z.name,
                                   sha256=str(n) * 64, stored_path=str(z), custody={})
        process_bundle(config.get_settings(), cid)
    html = TestClient(main.app).get("/report?host=PC-D").text
    sections = {
        "certificados": html[html.index("Certificados sinalizados"):html.index("Linha do tempo de atividade")],
        "linha do tempo": html[html.index("Linha do tempo de atividade"):html.index("<h2>Achados")],
        "achados": html[html.index("<h2>Achados"):html.index("<h2>Acessos remotos")],
    }
    for name, part in sections.items():
        assert part.count("POSTO Z LTDA:12614598000198") == 1, name
    assert "16/11/2026 14:16" in html
