import httpx
import pytest
from fastapi.testclient import TestClient

from app import config, db, llm, main


@pytest.fixture
def client(settings, monkeypatch):
    monkeypatch.setattr(main, "enqueue", lambda cid: None)
    monkeypatch.setattr(main, "enqueue_retriage", lambda: None)
    return TestClient(main.app)


ORIGIN = {"Origin": "https://testserver"}


def test_admin_page_renders_without_exposing_key(client, settings):
    db.set_setting(settings, "llm_api_key", "sk-or-v1-" + "f6" * 32)
    page = client.get("/admin")
    assert page.status_code == 200
    assert "f6f6f6f6" not in page.text
    assert "configurada" in page.text


def test_save_settings_overrides_env(client, settings):
    resp = client.post("/admin", headers=ORIGIN, data={
        "own_cnpjs": "11.222.333/0001-81, 07999649000107",
        "llm_base_url": "https://openrouter.ai/api/v1",
        "llm_model": "deepseek/deepseek-chat",
        "llm_api_key": "sk-or-v1-" + "a7" * 32,
        "llm_min_score": "3",
    }, follow_redirects=False)
    assert resp.status_code == 303
    eff = config.effective(settings)
    assert eff.own_cnpjs == frozenset({"11222333000181", "07999649000107"})
    assert eff.llm_base_url == "https://openrouter.ai/api/v1"
    assert eff.llm_model == "deepseek/deepseek-chat"
    assert eff.llm_min_score == 3
    assert eff.llm_api_key.startswith("sk-or-v1-")


def test_blank_key_keeps_existing(client, settings):
    db.set_setting(settings, "llm_api_key", "sk-or-v1-keep")
    client.post("/admin", headers=ORIGIN, data={"own_cnpjs": "", "llm_base_url": "",
                                                "llm_model": "", "llm_api_key": "",
                                                "llm_min_score": "5"})
    assert config.effective(settings).llm_api_key == "sk-or-v1-keep"


def test_clear_key_checkbox_removes_key(client, settings):
    db.set_setting(settings, "llm_api_key", "sk-or-v1-old")
    client.post("/admin", headers=ORIGIN, data={"own_cnpjs": "", "llm_base_url": "",
                                                "llm_model": "", "llm_api_key": "",
                                                "llm_min_score": "5", "clear_key": "1"})
    assert config.effective(settings).llm_api_key == ""


def test_post_without_same_origin_is_rejected(client):
    resp = client.post("/admin", headers={"Origin": "https://evil.example"},
                       data={"own_cnpjs": "", "llm_min_score": "5"})
    assert resp.status_code == 403


def test_openrouter_request_denies_data_collection(settings):
    db.set_setting(settings, "llm_base_url", "https://openrouter.ai/api/v1")
    db.set_setting(settings, "llm_model", "deepseek/deepseek-chat")
    db.set_setting(settings, "llm_api_key", "k")
    seen = {}

    def handler(request):
        import json
        seen.update(json.loads(request.content))
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"choices": [{"message": {
            "content": '{"label": "suspeito", "reason": "ok"}'}}]})

    eff = config.effective(settings)
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        result = llm.chat(eff, "teste", client=http)
    assert result == '{"label": "suspeito", "reason": "ok"}'
    assert seen["provider"]["data_collection"] == "deny"
    assert seen["auth"] == "Bearer k"


def test_llm_test_endpoint_reports_failure_without_key(client):
    resp = client.post("/admin/test-llm", headers=ORIGIN)
    assert resp.status_code == 200
    assert "não configurada" in resp.text
