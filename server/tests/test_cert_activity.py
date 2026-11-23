import json
import zipfile

from app import config, db
from app.certs import analyze_activity
from app.pipeline import process_bundle
from tests.conftest import make_bundle


def act(**kw):
    base = {"type": "lnk_aberto", "ts": "2026-11-05T15:20:00Z", "profile": "joao",
            "source": "recent", "path": r"C:\Users\joao\Downloads\bonanza.pfx",
            "file_name": "bonanza.pfx", "detail": "arquivo aberto"}
    base.update(kw)
    return base


def ids(found):
    return {f.rule_id for f in found}


def test_opened_cert_file():
    assert ids(analyze_activity(act())) == {"cert_arquivo_aberto"}


def test_export_command_is_high():
    found = analyze_activity(act(type="historico_comando", source="psreadline",
                                 detail="Export-PfxCertificate -Cert $c -FilePath C:\\t\\a.pfx"))
    assert "cert_exportado" in ids(found)
    assert next(f for f in found if f.rule_id == "cert_exportado").severity == "alta"


def test_certutil_export_is_high():
    found = analyze_activity(act(type="historico_comando", detail="certutil -exportPFX My 1234 out.pfx"))
    assert "cert_exportado" in ids(found)


def test_import_command_is_medium():
    found = analyze_activity(act(type="historico_comando", detail="Import-PfxCertificate -FilePath x.pfx"))
    assert ids(found) == {"cert_importado"}


def test_remote_transfer_line_is_high():
    found = analyze_activity(act(type="acesso_remoto_arquivo", source="anydesk",
                                 detail="2026-11-05 15:18 file transfer: bonanza.pfx (2.1 KB)"))
    assert next(f for f in found if f.rule_id == "cert_transferido_remoto").severity == "alta"


def test_recycle_bin_is_high():
    found = analyze_activity(act(type="cert_na_lixeira", source="lixeira"))
    assert "cert_apagado" in ids(found)


def test_key_migration_event_is_high():
    found = analyze_activity(act(type="evento_windows", source="Security", event_id=5059,
                                 detail="Key migration operation"))
    assert "cert_chave_exportada_evento" in ids(found)


def test_lifecycle_install_event_is_medium():
    found = analyze_activity(act(type="evento_windows",
                                 source="Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational",
                                 event_id=1006, detail="A certificate was installed"))
    assert "cert_instalado_evento" in ids(found)


def test_tool_execution_and_key_creation_are_low():
    assert ids(analyze_activity(act(type="execucao_ferramenta", file_name="CERTUTIL.EXE"))) == {"cert_ferramenta_executada"}
    found = analyze_activity(act(type="chave_privada_criada", source="crypto_keys"))
    assert ids(found) == {"cert_chave_privada_criada"}
    assert all(f.severity == "baixa" for f in found)


def test_unknown_type_ignored():
    assert analyze_activity(act(type="qualquer")) == []


def test_pipeline_ingests_activity_and_lists_timeline(settings, tmp_path):
    z = make_bundle(tmp_path, "SUP-1", {})
    with zipfile.ZipFile(z, "a") as zf:
        zf.writestr("cert_activity.json", json.dumps([
            act(),
            act(type="acesso_remoto_arquivo", source="anydesk", ts="2026-11-05T15:18:00Z",
                detail="file transfer bonanza.pfx"),
        ]))
    cid = db.create_collection(config.get_settings(), host="SUP-1", filename=z.name,
                               sha256="z" * 64, stored_path=str(z), custody={})
    stats = process_bundle(config.get_settings(), cid)
    assert stats["findings"] >= 2
    timeline = db.list_cert_activity(config.get_settings(), host="SUP-1")
    assert [t["ts"][:16] for t in timeline] == ["2026-11-05T15:18", "2026-11-05T15:20"]
    assert timeline[0]["rule_ids"] == "cert_transferido_remoto"
