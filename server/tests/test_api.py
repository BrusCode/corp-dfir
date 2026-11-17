import hashlib
import os
import stat

import pytest
from fastapi.testclient import TestClient

from app import db, main
from tests.conftest import make_bundle

KEY = "sk-or-v1-" + "d4" * 32


@pytest.fixture
def client(settings, monkeypatch):
    queued = []
    monkeypatch.setattr(main, "enqueue", lambda cid: queued.append(cid))
    c = TestClient(main.app)
    c.queued = queued
    return c


def _upload(client, zpath, token="test-token", sha=None):
    data = zpath.read_bytes()
    return client.post(
        "/api/v1/upload",
        files={"file": (zpath.name, data, "application/zip")},
        headers={"X-DFIR-Token": token,
                 "X-DFIR-SHA256": sha or hashlib.sha256(data).hexdigest()},
    )


def test_upload_requires_token(client, tmp_path):
    z = make_bundle(tmp_path, "PC-X", {"a.txt": ("ia", "oi")})
    assert _upload(client, z, token="errado").status_code == 401


def test_upload_rejects_hash_mismatch(client, tmp_path):
    z = make_bundle(tmp_path, "PC-X", {"a.txt": ("ia", "oi")})
    assert _upload(client, z, sha="0" * 64).status_code == 400


def test_upload_rejects_non_bundle(client, tmp_path):
    bad = tmp_path / "x.zip"
    bad.write_bytes(b"not a zip")
    assert _upload(client, bad).status_code == 400


def test_valid_upload_stored_readonly_and_queued(client, settings, tmp_path):
    z = make_bundle(tmp_path, "JHONS-SUPWP", {"a.txt": ("ia", "oi")})
    resp = _upload(client, z)
    assert resp.status_code == 201
    cid = resp.json()["collection_id"]
    col = db.get_collection(settings, cid)
    assert col["host"] == "JHONS-SUPWP"
    mode = os.stat(col["stored_path"]).st_mode
    assert not (mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
    assert client.queued == [cid]


def test_duplicate_upload_is_idempotent(client, tmp_path):
    z = make_bundle(tmp_path, "PC-X", {"a.txt": ("ia", "oi")})
    first = _upload(client, z).json()["collection_id"]
    second = _upload(client, z)
    assert second.status_code == 200
    assert second.json()["collection_id"] == first


def test_dashboard_and_exports(client, settings, tmp_path):
    from app.pipeline import process_bundle
    z = make_bundle(tmp_path, "PC-Y", {".env": ("segredo", f"OPENROUTER_API_KEY={KEY}")})
    cid = _upload(client, z).json()["collection_id"]
    process_bundle(settings, cid)
    page = client.get("/")
    assert page.status_code == 200 and "PC-Y" in page.text
    findings = client.get("/findings?host=PC-Y")
    assert "openrouter_key" in findings.text and KEY not in findings.text
    csv = client.get("/export/findings.csv")
    assert csv.status_code == 200 and "openrouter_key" in csv.text and KEY not in csv.text
    assert client.get("/secrets").status_code == 200
    assert client.get("/remote").status_code == 200
    assert client.get("/certs").status_code == 200
    assert client.get("/healthz").json() == {"ok": True}
