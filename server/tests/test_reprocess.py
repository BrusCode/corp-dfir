import hashlib
import json
import zipfile

from fastapi.testclient import TestClient

from app import config, db, main
from app.pipeline import process_bundle

KEY = "sk-or-v1-" + "a1" * 32
ORIGIN = {"Origin": "https://testserver"}


def backslash_bundle(tmp_path, host="WIN-HOST"):
    """Bundle whose entry names use backslashes, as some .NET versions write them."""
    z = tmp_path / f"CorpDFIR-{host}.zip"
    data = f"OPENROUTER_API_KEY={KEY}".encode()
    remote = b"Incoming 2026-11-05, 15:11 User 123456789 987654321"
    manifest = [
        {"profile": "k", "category": "segredo", "original_path": r"C:\Users\k\.env",
         "archive_path": "files/k/Users/k/.env", "size": len(data),
         "sha256": hashlib.sha256(data).hexdigest(), "status": "copied"},
        {"profile": "k", "category": "acesso_remoto",
         "original_path": r"C:\Users\k\AppData\Roaming\AnyDesk\connection_trace.txt",
         "archive_path": "files/k/Users/k/AppData/Roaming/AnyDesk/connection_trace.txt",
         "size": len(remote), "sha256": hashlib.sha256(remote).hexdigest(), "status": "copied"},
        {"profile": "k", "category": "ia", "original_path": r"C:\Users\k\.claude\x.jsonl",
         "archive_path": "files/k/Users/k/.claude/x.jsonl", "size": 0, "sha256": None,
         "status": "skipped_too_large"},
    ]
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("files\\k\\Users\\k\\.env", data)
        zf.writestr("files\\k\\Users\\k\\AppData\\Roaming\\AnyDesk\\connection_trace.txt", remote)
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr("custody.json", json.dumps({"hostname": host}))
    return z


def _register(z, host="WIN-HOST"):
    return db.create_collection(config.get_settings(), host=host, filename=z.name,
                                sha256=hashlib.sha256(z.read_bytes()).hexdigest(),
                                stored_path=str(z), custody={"hostname": host})


def test_backslash_entries_are_found_and_stats_recorded(settings, tmp_path):
    z = backslash_bundle(tmp_path)
    cid = _register(z)
    stats = process_bundle(config.get_settings(), cid)
    assert stats["missing_in_bundle"] == 0
    assert stats["files_by_category"] == {"segredo": 1, "acesso_remoto": 1}
    assert stats["skipped_by_status"] == {"skipped_too_large": 1}
    assert stats["events_by_category"]["acesso_remoto"] >= 1
    rules = {f["rule_id"] for f in db.list_findings(config.get_settings(), collection_id=cid)}
    assert "openrouter_key" in rules
    stored = db.get_collection(config.get_settings(), cid)
    assert json.loads(stored["stats"])["files_by_category"]["segredo"] == 1


def test_reprocess_replaces_derived_data(settings, tmp_path, monkeypatch):
    z = backslash_bundle(tmp_path)
    cid = _register(z)
    process_bundle(config.get_settings(), cid)
    before = len(db.list_findings(config.get_settings(), collection_id=cid))
    db.clear_collection_results(config.get_settings(), cid)
    assert db.list_findings(config.get_settings(), collection_id=cid) == []
    process_bundle(config.get_settings(), cid)
    assert len(db.list_findings(config.get_settings(), collection_id=cid)) == before


def test_reprocess_route(settings, tmp_path, monkeypatch):
    queued = []
    monkeypatch.setattr(main, "enqueue", lambda cid: queued.append(cid))
    client = TestClient(main.app)
    z = backslash_bundle(tmp_path)
    cid = _register(z)
    process_bundle(config.get_settings(), cid)
    assert client.post(f"/collections/{cid}/reprocess", headers={"Origin": "https://evil"}).status_code == 403
    r = client.post(f"/collections/{cid}/reprocess", headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303 and queued == [cid]
    assert db.get_collection(config.get_settings(), cid)["status"] == "queued"
    assert db.list_findings(config.get_settings(), collection_id=cid) == []
    page = client.get("/")
    assert "Reprocessar" in page.text
