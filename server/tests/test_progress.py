from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import db, main

TOKEN = {"X-DFIR-Token": "test-token"}


@pytest.fixture
def client(settings, monkeypatch):
    monkeypatch.setattr(main, "enqueue", lambda cid: None)
    return TestClient(main.app)


def beat(**kw):
    body = {"run_id": "run-1", "host": "WP-CASTILHO", "collector": "cert", "version": "cert-1.1.0",
            "step": "inicio", "status": "ok", "percent": 0, "detail": ""}
    body.update(kw)
    return body


def test_progress_requires_token(client):
    assert client.post("/api/v1/progress", json=beat()).status_code == 401
    assert client.post("/api/v1/progress", json=beat(), headers={"X-DFIR-Token": "x"}).status_code == 401


def test_progress_tracks_current_step_and_history(client, settings):
    for step, pct in (("inicio", 0), ("arquivos", 30), ("arquivos", 42)):
        r = client.post("/api/v1/progress", headers=TOKEN,
                        json=beat(step=step, percent=pct, detail=f"{pct}"))
        assert r.status_code == 204
    runs = db.list_runs(settings)
    assert len(runs) == 1
    run = runs[0]
    assert run["step"] == "arquivos" and run["percent"] == 42 and run["host"] == "WP-CASTILHO"
    assert run["state"] == "em_andamento"
    history = db.run_history(settings, "run-1")
    assert [h["percent"] for h in history] == [0, 30, 42]


def test_final_step_marks_finished_or_failed(client, settings):
    client.post("/api/v1/progress", headers=TOKEN, json=beat(step="fim", percent=100))
    assert db.list_runs(settings)[0]["state"] == "concluido"
    client.post("/api/v1/progress", headers=TOKEN,
                json=beat(run_id="run-2", step="falha", status="erro", detail="linha 12: x"))
    assert {r["run_id"]: r["state"] for r in db.list_runs(settings)}["run-2"] == "falhou"
    client.post("/api/v1/progress", headers=TOKEN,
                json=beat(run_id="run-3", step="fim", status="erro", percent=100, detail="pendentes=1"))
    assert {r["run_id"]: r["state"] for r in db.list_runs(settings)}["run-3"] == "concluido_com_erro"


def test_stale_run_flagged(client, settings):
    client.post("/api/v1/progress", headers=TOKEN, json=beat(step="arquivos", percent=20))
    old = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    with db.connect(settings) as con:
        con.execute("UPDATE runs SET updated_at=?", (old,))
    assert db.list_runs(settings)[0]["state"] == "sem_sinal"


def test_percent_clamped_and_fields_bounded(client, settings):
    client.post("/api/v1/progress", headers=TOKEN, json=beat(percent=250, detail="x" * 5000))
    run = db.list_runs(settings)[0]
    assert run["percent"] == 100 and len(run["detail"]) <= 1000


def test_runs_page_and_json(client, settings):
    client.post("/api/v1/progress", headers=TOKEN, json=beat(step="eventos", percent=70))
    page = client.get("/runs")
    assert page.status_code == 200 and "WP-CASTILHO" in page.text and "eventos" in page.text
    assert client.get("/runs/run-1").status_code == 200
    assert client.get("/").status_code == 200
