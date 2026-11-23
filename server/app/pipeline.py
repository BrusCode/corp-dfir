"""Process one collection: extract into a work area, parse, detect and optionally triage."""

import json
import shutil
import zipfile
from pathlib import Path

from app import config, db, llm
from app.certs import analyze_activity, analyze_cert, describe, describe_activity
from app.config import Settings
from app.parsers import parse_file, skip_reason
from app.rules import load_rules, mask_secrets, scan_text


def _safe_extract(zpath: Path, dest: Path) -> None:
    """Extract with "/" paths even when the zip was written with "\\" (some .NET versions do)."""
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with zipfile.ZipFile(zpath) as zf:
        for member in zf.infolist():
            name = member.filename.replace("\\", "/")
            if name.endswith("/"):
                continue
            target = (dest / name).resolve()
            if not str(target).startswith(str(root) + "/"):
                raise ValueError(f"caminho inválido no zip: {member.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as src, target.open("wb") as out:
                shutil.copyfileobj(src, out)


def process_bundle(settings: Settings, collection_id: int) -> dict:
    settings = config.effective(settings)
    collection = db.get_collection(settings, collection_id)
    host = collection["host"]
    work = settings.work_dir / str(collection_id)
    rules = load_rules()
    stats = {"files": 0, "events": 0, "findings": 0, "triaged": 0, "missing_in_bundle": 0,
             "files_by_category": {}, "skipped_by_status": {}, "events_by_category": {}}

    def bump(key: str, sub: str, n: int = 1) -> None:
        stats[key][sub] = stats[key].get(sub, 0) + n
    db.set_status(settings, collection_id, "processing")
    try:
        if work.exists():
            shutil.rmtree(work)
        _safe_extract(Path(collection["stored_path"]), work)
        manifest = json.loads((work / "manifest.json").read_text(encoding="utf-8"))
        db.insert_files(settings, collection_id, manifest)
        with db.connect(settings) as con:
            for entry in manifest:
                if entry.get("status") != "copied" or not entry.get("archive_path"):
                    bump("skipped_by_status", str(entry.get("status") or "sem_status"))
                    continue
                path = work / entry["archive_path"].replace("\\", "/")
                stats["files"] += 1
                if not path.is_file():
                    stats["missing_in_bundle"] += 1
                    db.set_file_note(con, collection_id, entry.get("original_path"), "não encontrado no pacote")
                    continue
                bump("files_by_category", entry.get("category") or "?")
                parsed = parse_file(path, entry.get("category", ""))
                if not parsed:
                    db.set_file_note(con, collection_id, entry.get("original_path"),
                                     skip_reason(path, entry.get("category", "")))
                for event in parsed:
                    ctx = {"host": host, "profile": entry.get("profile"),
                           "source": event.source, "ts": event.ts or entry.get("mtime"),
                           "original_path": entry.get("original_path")}
                    findings = scan_text(event.text, rules)
                    # Events are stored with secrets masked; the raw value stays in the evidence.
                    stored_text = mask_secrets(event.text, rules)
                    event_id = db.insert_event(
                        con, collection_id, category=entry.get("category"), role=event.role,
                        location=event.location, text=stored_text[:100_000], **ctx)
                    stats["events"] += 1
                    bump("events_by_category", entry.get("category") or "?")
                    for f in findings:
                        db.insert_finding(con, collection_id, event_id, f, **ctx)
                        stats["findings"] += 1
        certs_file = work / "certs.json"
        if certs_file.exists():
            records = json.loads(certs_file.read_text(encoding="utf-8-sig") or "[]")
            if isinstance(records, dict):
                records = [records]
            with db.connect(settings) as con:
                for record in records:
                    found = analyze_cert(record, set(settings.own_cnpjs))
                    verdict = ",".join(sorted({f.rule_id for f in found}))
                    db.insert_certificate(con, collection_id, host, record, verdict)
                    if not found:
                        continue
                    ctx = {"host": host, "profile": record.get("profile"),
                           "source": "certificado", "ts": record.get("file_created"),
                           "original_path": record.get("path") or record.get("origin")}
                    event_id = db.insert_event(con, collection_id, category="certificado",
                                               role=None, location=record.get("origin"),
                                               text=describe(record), **ctx)
                    stats["events"] += 1
                    for f in found:
                        db.insert_finding(con, collection_id, event_id, f, **ctx)
                        stats["findings"] += 1
                # Without the certificate collector's activity file (e.g. a bundle from the main
                # collector), build the timeline from the inventory dates.
                if not (work / "cert_activity.json").exists():
                    for record in records:
                        _inventory_timeline_event(con, collection_id, host, record, stats)
        activity_file = work / "cert_activity.json"
        if activity_file.exists():
            records = json.loads(activity_file.read_text(encoding="utf-8-sig") or "[]")
            if isinstance(records, dict):
                records = [records]
            with db.connect(settings) as con:
                for record in records:
                    ctx = {"host": host, "profile": record.get("profile"),
                           "source": str(record.get("source") or "certificado")[:100],
                           "ts": record.get("ts"),
                           "original_path": record.get("path") or record.get("source")}
                    event_id = db.insert_event(con, collection_id, category="certificado_atividade",
                                               role=record.get("type"), location=record.get("source"),
                                               text=mask_secrets(describe_activity(record), rules), **ctx)
                    stats["events"] += 1
                    for f in analyze_activity(record):
                        db.insert_finding(con, collection_id, event_id, f, **ctx)
                        stats["findings"] += 1
        if llm.enabled(settings):
            for finding in db.list_findings(settings, collection_id=collection_id):
                result = llm.triage_finding(settings, finding, rules)
                if result:
                    db.set_triage(settings, finding["id"], *result)
                    stats["triaged"] += 1
        db.set_status(settings, collection_id, "done", stats=stats)
        return stats
    except Exception as exc:
        db.set_status(settings, collection_id, "error", f"{type(exc).__name__}: {exc}"[:500])
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)



def retriage_pending(settings: Settings) -> int:
    """Run (or rerun after errors) the LLM triage on stored findings above the threshold."""
    settings = config.effective(settings)
    if not llm.enabled(settings):
        return 0
    rules = load_rules()
    done = 0
    for finding in db.findings_for_triage(settings, settings.llm_min_score):
        result = llm.triage_finding(settings, finding, rules)
        if result:
            db.set_triage(settings, finding["id"], *result)
            done += 1
    return done


def _inventory_timeline_event(con, collection_id: int, host: str, record: dict, stats: dict) -> None:
    origin = record.get("origin") or ""
    if not record.get("file_created"):
        return
    if origin.startswith("store:CurrentUser"):
        kind, what = "certificado_instalado", "instalado no repositório do usuário"
    elif origin == "file":
        kind, what = "arquivo_certificado", "arquivo criado na máquina"
    else:
        return
    detail = what
    if record.get("host_url"):
        detail += f"; baixado de {record['host_url']}"
    text = " | ".join(x for x in (kind, record.get("subject") or "", record.get("path") or "", detail) if x)
    db.insert_event(con, collection_id, category="certificado_atividade", role=kind,
                    location="inventario", text=text[:4000], host=host,
                    profile=record.get("profile"), source="inventario",
                    ts=record.get("file_created"), original_path=record.get("path") or origin)
    stats["events"] += 1
