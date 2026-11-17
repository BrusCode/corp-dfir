"""HTTP API (upload from the collector) and read-only dashboard."""

import csv
import hashlib
import hmac
import io
import json
import os
import re
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from app import config, db, llm
from app.config import get_settings


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init_db(get_settings())
    yield


app = FastAPI(title="Corp-DFIR", docs_url=None, redoc_url=None, lifespan=lifespan)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")
CHUNK = 1024 * 1024


def _kick(task_name: str, *args) -> None:
    import asyncio

    from app import tasks

    async def _run():
        await tasks.broker.startup()
        try:
            await getattr(tasks, task_name).kiq(*args)
        finally:
            await tasks.broker.shutdown()

    asyncio.run(_run())


def enqueue(collection_id: int) -> None:
    """Hand the collection to the worker (replaced in tests)."""
    _kick("process_upload", collection_id)


def enqueue_retriage() -> None:
    _kick("retriage")


def _require_same_origin(request: Request) -> None:
    """Block cross-site form posts against the Basic-Auth panel."""
    origin = request.headers.get("origin") or request.headers.get("referer") or ""
    host = request.headers.get("host", "")
    if not origin or origin.split("://", 1)[-1].split("/", 1)[0] != host:
        raise HTTPException(403, "origem não permitida")


def _read_custody(path: Path) -> dict:
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
            if "manifest.json" not in names or "custody.json" not in names:
                raise ValueError("pacote sem manifest.json/custody.json")
            return json.loads(zf.read("custody.json").decode("utf-8-sig"))
    except (zipfile.BadZipFile, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(400, f"pacote inválido: {exc}") from exc


@app.post("/api/v1/upload", status_code=201)
def upload(
    file: UploadFile = File(...),
    x_dfir_token: str = Header(default=""),
    x_dfir_sha256: str = Header(default=""),
):
    settings = get_settings()
    if not settings.upload_token or not hmac.compare_digest(x_dfir_token, settings.upload_token):
        raise HTTPException(401, "token inválido")
    expected = x_dfir_sha256.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise HTTPException(400, "X-DFIR-SHA256 ausente ou inválido")

    for existing in db.list_collections(settings):
        if existing["sha256"] == expected:
            return JSONResponse({"collection_id": existing["id"], "duplicate": True}, 200)

    incoming = settings.evidence_dir / "_incoming"
    incoming.mkdir(parents=True, exist_ok=True)
    tmp = incoming / f"{expected}.part"
    digest, size = hashlib.sha256(), 0
    with tmp.open("wb") as out:
        while chunk := file.file.read(CHUNK):
            size += len(chunk)
            if size > settings.max_upload_bytes:
                out.close()
                tmp.unlink(missing_ok=True)
                raise HTTPException(413, "pacote acima do limite")
            digest.update(chunk)
            out.write(chunk)
    if digest.hexdigest() != expected:
        tmp.unlink(missing_ok=True)
        raise HTTPException(400, "SHA-256 não confere com o conteúdo recebido")

    try:
        custody = _read_custody(tmp)
    except HTTPException:
        tmp.unlink(missing_ok=True)
        raise
    host = SAFE_NAME.sub("_", str(custody.get("hostname") or "desconhecido"))[:64]
    host_dir = settings.evidence_dir / host
    host_dir.mkdir(parents=True, exist_ok=True)
    stored = host_dir / SAFE_NAME.sub("_", file.filename or f"{expected}.zip")
    if stored.exists():
        stored = host_dir / f"{expected[:12]}-{stored.name}"
    tmp.replace(stored)
    os.chmod(stored, 0o444)

    custody["received_sha256"] = expected
    custody["received_bytes"] = size
    cid = db.create_collection(settings, host=host, filename=stored.name, sha256=expected,
                               stored_path=str(stored), custody=custody)
    enqueue(cid)
    return {"collection_id": cid, "host": host}


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    settings = get_settings()
    return templates.TemplateResponse(request, "index.html", {
        "collections": db.list_collections(settings),
        "secrets": db.correlated_secrets(settings)[:10],
    })


@app.get("/findings", response_class=HTMLResponse)
def findings(request: Request, host: str = "", severity: str = "", category: str = "",
             collection_id: int | None = None):
    settings = get_settings()
    rows = db.list_findings(settings, collection_id=collection_id, host=host,
                            severity=severity, category=category)
    return templates.TemplateResponse(request, "findings.html", {
        "rows": rows, "host": host, "severity": severity, "category": category,
    })


@app.get("/secrets", response_class=HTMLResponse)
def secrets(request: Request):
    return templates.TemplateResponse(request, "secrets.html",
                                      {"rows": db.correlated_secrets(get_settings())})


@app.get("/remote", response_class=HTMLResponse)
def remote(request: Request, host: str = ""):
    return templates.TemplateResponse(request, "remote.html",
                                      {"rows": db.remote_events(get_settings(), host), "host": host})


@app.get("/certs", response_class=HTMLResponse)
def certs(request: Request, host: str = ""):
    return templates.TemplateResponse(request, "certs.html",
                                      {"rows": db.list_certificates(get_settings(), host), "host": host})


@app.get("/export/findings.csv")
def export_csv(host: str = "", severity: str = "", category: str = ""):
    rows = db.list_findings(get_settings(), host=host, severity=severity, category=category,
                            limit=100_000)
    columns = ["id", "host", "profile", "source", "ts", "rule_id", "category", "severity",
               "score", "masked", "fingerprint", "original_path", "snippet",
               "triage_label", "triage_reason"]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=findings.csv"})


@app.get("/export/findings.json")
def export_json(host: str = "", severity: str = "", category: str = ""):
    return db.list_findings(get_settings(), host=host, severity=severity, category=category,
                            limit=100_000)


@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request, msg: str = "", ok: int = 1):
    eff = config.effective(get_settings())
    return templates.TemplateResponse(request, "admin.html", {
        "own_cnpjs": ", ".join(sorted(eff.own_cnpjs)),
        "llm_base_url": eff.llm_base_url,
        "llm_model": eff.llm_model,
        "llm_min_score": eff.llm_min_score,
        "key_set": bool(eff.llm_api_key),
        "key_hint": (eff.llm_api_key[:9] + "…" + eff.llm_api_key[-4:]) if len(eff.llm_api_key) > 16 else "",
        "llm_on": llm.enabled(eff),
        "msg": msg, "ok": ok,
    })


@app.post("/admin")
def admin_save(
    request: Request,
    own_cnpjs: str = Form(""),
    llm_base_url: str = Form(""),
    llm_model: str = Form(""),
    llm_api_key: str = Form(""),
    llm_min_score: str = Form("5"),
    clear_key: str = Form(""),
):
    _require_same_origin(request)
    settings = get_settings()
    db.set_setting(settings, "own_cnpjs", ",".join(sorted(config.parse_cnpjs(own_cnpjs))))
    db.set_setting(settings, "llm_base_url", llm_base_url.strip())
    db.set_setting(settings, "llm_model", llm_model.strip())
    db.set_setting(settings, "llm_min_score", llm_min_score.strip() if llm_min_score.strip().isdigit() else "5")
    if clear_key:
        db.set_setting(settings, "llm_api_key", "")
    elif llm_api_key.strip():
        db.set_setting(settings, "llm_api_key", llm_api_key.strip())
    return RedirectResponse("/admin?msg=Configurações+salvas", status_code=303)


@app.post("/admin/test-llm", response_class=HTMLResponse)
def admin_test_llm(request: Request):
    _require_same_origin(request)
    good, message = llm.test_connection(config.effective(get_settings()))
    return admin(request, msg=message, ok=int(good))


@app.post("/admin/retriage")
def admin_retriage(request: Request):
    _require_same_origin(request)
    enqueue_retriage()
    return RedirectResponse("/admin?msg=Triagem+enfileirada+para+os+achados+pendentes", status_code=303)
