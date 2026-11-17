"""Process one collection: extract into a work area, parse, detect and optionally triage."""

import json
import shutil
import zipfile
from pathlib import Path

from app import db, llm
from app.certs import analyze_cert, describe
from app.config import Settings
from app.parsers import parse_file
from app.rules import load_rules, scan_text


def _safe_extract(zpath: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with zipfile.ZipFile(zpath) as zf:
        for member in zf.infolist():
            target = (dest / member.filename).resolve()
            if not str(target).startswith(str(root)):
                raise ValueError(f"caminho inválido no zip: {member.filename}")
        zf.extractall(dest)


def process_bundle(settings: Settings, collection_id: int) -> dict:
    collection = db.get_collection(settings, collection_id)
    host = collection["host"]
    work = settings.work_dir / str(collection_id)
    rules = load_rules()
    stats = {"files": 0, "events": 0, "findings": 0, "triaged": 0}
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
                    continue
                path = work / entry["archive_path"]
                stats["files"] += 1
                for event in parse_file(path, entry.get("category", "")):
                    ctx = {"host": host, "profile": entry.get("profile"),
                           "source": event.source, "ts": event.ts or entry.get("mtime"),
                           "original_path": entry.get("original_path")}
                    findings = scan_text(event.text, rules)
                    # Events are stored with secrets masked; the raw value stays in the evidence.
                    stored_text = event.text
                    for f in findings:
                        if f.masked:
                            stored_text = stored_text.replace(
                                _raw_value(event.text, f), f.masked)
                    event_id = db.insert_event(
                        con, collection_id, category=entry.get("category"), role=event.role,
                        location=event.location, text=stored_text[:100_000], **ctx)
                    stats["events"] += 1
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
        if llm.enabled(settings):
            for finding in db.list_findings(settings, collection_id=collection_id):
                result = llm.triage_finding(settings, finding, rules)
                if result:
                    db.set_triage(settings, finding["id"], *result)
                    stats["triaged"] += 1
        db.set_status(settings, collection_id, "done")
        return stats
    except Exception as exc:
        db.set_status(settings, collection_id, "error", f"{type(exc).__name__}: {exc}"[:500])
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _raw_value(text: str, finding) -> str:
    """Find the raw secret behind a masked finding so it can be replaced in stored text."""
    from app.masking import fingerprint
    for rule in load_rules():
        if rule.id != finding.rule_id:
            continue
        for match in rule.pattern.finditer(text):
            if fingerprint(match.group(0)) == finding.fingerprint:
                return match.group(0)
    return "\0"
