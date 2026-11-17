import json

from app import db
from app.pipeline import process_bundle
from tests.conftest import make_bundle

KEY = "sk-or-v1-" + "c3" * 32


def _register(settings, zpath, host):
    return db.create_collection(settings, host=host,
                                filename=zpath.name, sha256="x" * 64,
                                stored_path=str(zpath), custody={})


def test_bundle_produces_events_and_masked_findings(settings, tmp_path):
    session = json.dumps({"type": "user", "timestamp": "2026-11-05T12:00:00Z",
                          "message": {"role": "user", "content": f"usa essa chave {KEY}"}})
    zpath = make_bundle(tmp_path, "JHONS-SUPWP", {
        ".claude/projects/a/s.jsonl": ("ia", session),
        "AppData/Roaming/AnyDesk/connection_trace.txt":
            ("acesso_remoto", "Incoming 2026-11-05, 15:11 User 123456789 987654321"),
    })
    cid = _register(settings, zpath, "JHONS-SUPWP")
    stats = process_bundle(settings, cid)
    assert stats["events"] >= 2
    findings = db.list_findings(settings, collection_id=cid)
    key_findings = [f for f in findings if f["rule_id"] == "openrouter_key"]
    assert key_findings
    assert KEY not in json.dumps(findings)
    assert key_findings[0]["fingerprint"]
    assert db.get_collection(settings, cid)["status"] == "done"
    with db.connect(settings) as con:
        stored = " ".join(r["text"] for r in con.execute("SELECT text FROM events"))
    assert KEY not in stored
    assert key_findings[0]["masked"] in stored


def test_same_secret_correlated_across_hosts(settings, tmp_path):
    for host in ("PC-A", "PC-B"):
        folder = tmp_path / host
        folder.mkdir()
        z = make_bundle(folder, host, {".env": ("segredo", f"OPENROUTER_API_KEY={KEY}")})
        process_bundle(settings, _register(settings, z, host))
    groups = db.correlated_secrets(settings)
    assert any(g["hosts"] == 2 for g in groups)


def test_skipped_and_cert_entries_recorded_without_content(settings, tmp_path):
    zpath = make_bundle(tmp_path, "PC-C", {"notes.txt": ("ia", "nada demais aqui")})
    cid = _register(settings, zpath, "PC-C")
    process_bundle(settings, cid)
    files = db.list_files(settings, cid)
    assert files and files[0]["sha256"]
