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

from fastapi import FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from app import db
from app.config import get_settings

@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init_db(get_settings())
    yield


app = FastAPI(title="Corp-DFIR", docs_url=None, redoc_url=None, lifespan=lifespan)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")
CHUNK = 1024 * 1024


def enqueue(collection_id: int) -> None:
    """Hand the collection to the worker (replaced in tests)."""
    import asyncio

    from app.tasks import broker, process_upload

    async def _kick():
        await broker.startup()
        try:
            await process_upload.kiq(collection_id)
        finally:
            await broker.shutdown()

    asyncio.run(_kick())


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
