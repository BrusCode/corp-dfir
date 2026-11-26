import csv
import io
import json
import zipfile

from fastapi.testclient import TestClient

from app import config, db, main
from app.pipeline import process_bundle


def make(tmp_path, n, certs):
    folder = tmp_path / f"c{n}"
    folder.mkdir()
    z = folder / f"b{n}.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("manifest.json", "[]")
        zf.writestr("certs.json", json.dumps(certs))
        zf.writestr("custody.json", json.dumps({"hostname": "PC-E", "collector_version": f"v{n}"}))
    cid = db.create_collection(config.get_settings(), host="PC-E", filename=z.name, sha256=str(n) * 64,
                               stored_path=str(z), custody={"hostname": "PC-E", "collector_version": f"v{n}"})
    process_bundle(config.get_settings(), cid)
    return cid


def cert(cnpj, name):
    return {"origin": "store:CurrentUser\\My", "profile": "k", "path": f"C:\\x\\{cnpj}", "readable": True,
            "thumbprint": cnpj[:8] * 5, "subject": f"CN={name}:{cnpj}", "issuer": "CN=AC, O=ICP-Brasil",
            "has_private_key": True, "cnpj": cnpj, "file_created": "2026-11-16T17:16:27Z"}


def setup(settings, tmp_path, monkeypatch):
    monkeypatch.setattr(main, "enqueue", lambda cid: None)
    a = make(tmp_path, 1, [cert("11111111000111", "POSTO UM")])
    b = make(tmp_path, 2, [cert("22222222000122", "POSTO DOIS")])
    return TestClient(main.app), a, b


def test_report_scoped_to_one_collection(settings, tmp_path, monkeypatch):
    client, a, b = setup(settings, tmp_path, monkeypatch)
    html = client.get(f"/report?collection_id={a}").text
    assert "POSTO UM" in html and "POSTO DOIS" not in html
    assert "b2.zip" not in html  # custody only of the selected collection


def test_report_only_selected_sections(settings, tmp_path, monkeypatch):
    client, a, _ = setup(settings, tmp_path, monkeypatch)
    html = client.get(f"/report?collection_id={a}&sections=certificados").text
    assert "Certificados sinalizados" in html
    assert "Linha do tempo de atividade" not in html and "<h2>Achados" not in html


def test_csv_zip_per_section(settings, tmp_path, monkeypatch):
    client, a, _ = setup(settings, tmp_path, monkeypatch)
    resp = client.get(f"/export/data.zip?collection_id={a}&sections=certificados&sections=achados&sections=custodia")
    assert resp.status_code == 200 and "attachment" in resp.headers["content-disposition"]
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    assert sorted(zf.namelist()) == ["achados.csv", "certificados.csv", "custodia.csv"]
    rows = list(csv.DictReader(io.StringIO(zf.read("certificados.csv").decode("utf-8-sig")), delimiter=";"))
    assert len(rows) == 1 and rows[0]["cnpj"] == "11111111000111"
    assert rows[0]["criado_instalado"] == "16/11/2026 14:16:27"


def test_export_page_lists_collections(settings, tmp_path, monkeypatch):
    client, a, b = setup(settings, tmp_path, monkeypatch)
    page = client.get("/export").text
    assert f'value="{a}"' in page and f'value="{b}"' in page and "Certificados" in page
