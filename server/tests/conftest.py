import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from app import config, db


@pytest.fixture
def settings(tmp_path, monkeypatch):
    monkeypatch.setenv("DFIR_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("DFIR_UPLOAD_TOKEN", "test-token")
    monkeypatch.setenv("LLM_BASE_URL", "")
    config.get_settings.cache_clear()
    s = config.get_settings()
    db.init_db(s)
    yield s
    config.get_settings.cache_clear()


def make_bundle(tmp_path: Path, host: str, files: dict[str, tuple[str, str]]) -> Path:
    """files: archive_path -> (category, content). Mirrors the collector layout."""
    zpath = tmp_path / f"CorpDFIR-{host}-20261117T120000Z.zip"
    manifest = []
    with zipfile.ZipFile(zpath, "w") as zf:
        for arc, (category, content) in files.items():
            data = content.encode("utf-8")
            zf.writestr(f"files/{arc}", data)
            manifest.append({
                "profile": "joao", "category": category,
                "original_path": f"C:\\Users\\joao\\{arc}",
                "archive_path": f"files/{arc}", "size": len(data),
                "mtime": "2026-11-05T12:00:00Z",
                "sha256": hashlib.sha256(data).hexdigest(), "status": "copied",
            })
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr("custody.json", json.dumps({
            "hostname": host, "operator": "NT AUTHORITY\\SYSTEM",
            "collected_at": "2026-11-17T12:00:00Z", "collector_version": "1.0.0",
        }))
    return zpath
