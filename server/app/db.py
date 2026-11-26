"""SQLite storage: collections (custody), files (manifest), events and findings."""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from app.config import Settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS collections (
  id INTEGER PRIMARY KEY, host TEXT NOT NULL, filename TEXT NOT NULL,
  sha256 TEXT NOT NULL, stored_path TEXT NOT NULL, custody TEXT NOT NULL,
  received_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued', error TEXT
);
CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY, collection_id INTEGER NOT NULL REFERENCES collections(id),
  profile TEXT, category TEXT, original_path TEXT, size INTEGER, mtime TEXT,
  sha256 TEXT, status TEXT
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, collection_id INTEGER NOT NULL REFERENCES collections(id),
  host TEXT, profile TEXT, category TEXT, source TEXT, role TEXT, ts TEXT,
  original_path TEXT, location TEXT, text TEXT
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY, collection_id INTEGER NOT NULL REFERENCES collections(id),
  event_id INTEGER REFERENCES events(id), host TEXT, profile TEXT, source TEXT, ts TEXT,
  rule_id TEXT, category TEXT, severity TEXT, score INTEGER, snippet TEXT,
  masked TEXT, fingerprint TEXT, original_path TEXT,
  triage_label TEXT, triage_reason TEXT
);
CREATE TABLE IF NOT EXISTS certificates (
  id INTEGER PRIMARY KEY, collection_id INTEGER NOT NULL REFERENCES collections(id),
  host TEXT, profile TEXT, origin TEXT, path TEXT, readable INTEGER, thumbprint TEXT,
  subject TEXT, issuer TEXT, cnpj TEXT, not_after TEXT, has_private_key INTEGER,
  file_sha256 TEXT, file_created TEXT, zone_id INTEGER, host_url TEXT, referrer_url TEXT,
  verdict TEXT
);
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY, host TEXT, collector TEXT, version TEXT, started_at TEXT,
  updated_at TEXT, step TEXT, status TEXT, percent INTEGER, detail TEXT, finished INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS run_events (
  id INTEGER PRIMARY KEY, run_id TEXT NOT NULL, at TEXT, step TEXT, status TEXT,
  percent INTEGER, detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_run_events_run ON run_events(run_id);
CREATE TABLE IF NOT EXISTS analyses (
  id INTEGER PRIMARY KEY, scope_host TEXT NOT NULL DEFAULT '', status TEXT NOT NULL,
  created_at TEXT NOT NULL, finished_at TEXT, model TEXT, text TEXT, error TEXT, stats TEXT
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_events_coll ON events(collection_id);
"""


@contextmanager
def connect(settings: Settings):
    con = sqlite3.connect(settings.db_path, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    try:
        yield con
        con.commit()
    finally:
        con.close()


MIGRATIONS = ["ALTER TABLE collections ADD COLUMN stats TEXT",
              "ALTER TABLE files ADD COLUMN note TEXT"]


def init_db(settings: Settings) -> None:
    for path in (settings.data_dir, settings.evidence_dir, settings.work_dir):
        path.mkdir(parents=True, exist_ok=True)
    with connect(settings) as con:
        con.executescript(SCHEMA)
        for statement in MIGRATIONS:
            try:
                con.execute(statement)
            except sqlite3.OperationalError:
                pass  # already applied


def create_collection(settings, *, host, filename, sha256, stored_path, custody) -> int:
    with connect(settings) as con:
        cur = con.execute(
            "INSERT INTO collections (host, filename, sha256, stored_path, custody, received_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (host, filename, sha256, stored_path, json.dumps(custody),
             datetime.now(timezone.utc).isoformat()),
        )
        return cur.lastrowid


def set_status(settings, collection_id: int, status: str, error: str | None = None,
               stats: dict | None = None) -> None:
    with connect(settings) as con:
        if stats is None:
            con.execute("UPDATE collections SET status=?, error=? WHERE id=?",
                        (status, error, collection_id))
        else:
            con.execute("UPDATE collections SET status=?, error=?, stats=? WHERE id=?",
                        (status, error, json.dumps(stats), collection_id))


def clear_collection_results(settings, collection_id: int) -> None:
    """Remove everything derived from a bundle (the stored evidence itself is untouched)."""
    with connect(settings) as con:
        for table in ("findings", "events", "certificates", "files"):
            con.execute(f"DELETE FROM {table} WHERE collection_id=?", (collection_id,))
        con.execute("UPDATE collections SET status='queued', error=NULL, stats=NULL WHERE id=?",
                    (collection_id,))


def get_collection(settings, collection_id: int) -> dict | None:
    with connect(settings) as con:
        row = con.execute("SELECT * FROM collections WHERE id=?", (collection_id,)).fetchone()
        return dict(row) if row else None


def list_collections(settings) -> list[dict]:
    with connect(settings) as con:
        rows = con.execute(
            "SELECT c.*, (SELECT COUNT(*) FROM findings f WHERE f.collection_id=c.id) AS findings,"
            " (SELECT COUNT(*) FROM events e WHERE e.collection_id=c.id) AS events"
            " FROM collections c ORDER BY c.id DESC").fetchall()
        return [dict(r) for r in rows]


def insert_files(settings, collection_id: int, entries: list[dict]) -> None:
    with connect(settings) as con:
        con.executemany(
            "INSERT INTO files (collection_id, profile, category, original_path, size, mtime,"
            " sha256, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [(collection_id, e.get("profile"), e.get("category"), e.get("original_path"),
              e.get("size"), e.get("mtime"), e.get("sha256"), e.get("status")) for e in entries],
        )


def list_files(settings, collection_id: int) -> list[dict]:
    with connect(settings) as con:
        rows = con.execute("SELECT * FROM files WHERE collection_id=?", (collection_id,))
        return [dict(r) for r in rows]


def insert_event(con, collection_id: int, **fields) -> int:
    cur = con.execute(
        "INSERT INTO events (collection_id, host, profile, category, source, role, ts,"
        " original_path, location, text) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (collection_id, fields["host"], fields["profile"], fields["category"], fields["source"],
         fields["role"], fields["ts"], fields["original_path"], fields["location"],
         fields["text"]),
    )
    return cur.lastrowid


def insert_finding(con, collection_id: int, event_id: int, finding, **ctx) -> None:
    con.execute(
        "INSERT INTO findings (collection_id, event_id, host, profile, source, ts, rule_id,"
        " category, severity, score, snippet, masked, fingerprint, original_path)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (collection_id, event_id, ctx["host"], ctx["profile"], ctx["source"], ctx["ts"],
         finding.rule_id, finding.category, finding.severity, finding.score, finding.snippet,
         finding.masked, finding.fingerprint, ctx["original_path"]),
    )


def list_findings(settings, *, collection_id=None, host=None, severity=None,
                  category=None, limit=2000) -> list[dict]:
    query, params = "SELECT * FROM findings WHERE 1=1", []
    for column, value in (("collection_id", collection_id), ("host", host),
                          ("severity", severity), ("category", category)):
        if value not in (None, ""):
            query += f" AND {column}=?"
            params.append(value)
    query += " ORDER BY score DESC, id DESC LIMIT ?"
    params.append(limit)
    with connect(settings) as con:
        return [dict(r) for r in con.execute(query, params)]


def remote_events(settings, host=None, collection_id=None) -> list[dict]:
    query = "SELECT * FROM events WHERE category='acesso_remoto'"
    params = []
    if host:
        query += " AND host=?"
        params.append(host)
    if collection_id:
        query += " AND collection_id=?"
        params.append(collection_id)
    with connect(settings) as con:
        return [dict(r) for r in con.execute(query + " ORDER BY host, id", params)]


def event_context(settings, event_id: int, radius: int = 20) -> list[dict]:
    with connect(settings) as con:
        base = con.execute("SELECT collection_id, original_path FROM events WHERE id=?",
                           (event_id,)).fetchone()
        if not base:
            return []
        rows = con.execute(
            "SELECT * FROM events WHERE collection_id=? AND original_path=? AND id BETWEEN ? AND ?"
            " ORDER BY id",
            (base["collection_id"], base["original_path"], event_id - radius, event_id + radius))
        return [dict(r) for r in rows]


def set_triage(settings, finding_id: int, label: str, reason: str) -> None:
    with connect(settings) as con:
        con.execute("UPDATE findings SET triage_label=?, triage_reason=? WHERE id=?",
                    (label, reason, finding_id))


def correlated_secrets(settings) -> list[dict]:
    with connect(settings) as con:
        rows = con.execute(
            "SELECT fingerprint, rule_id, MIN(masked) AS masked, COUNT(DISTINCT host) AS hosts,"
            " GROUP_CONCAT(DISTINCT host) AS host_list, COUNT(*) AS occurrences"
            " FROM findings WHERE fingerprint IS NOT NULL"
            " GROUP BY fingerprint ORDER BY hosts DESC, occurrences DESC")
        return [dict(r) for r in rows]


def insert_certificate(con, collection_id: int, host: str, record: dict, verdict: str) -> None:
    con.execute(
        "INSERT INTO certificates (collection_id, host, profile, origin, path, readable,"
        " thumbprint, subject, issuer, cnpj, not_after, has_private_key, file_sha256,"
        " file_created, zone_id, host_url, referrer_url, verdict)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (collection_id, host, record.get("profile"), record.get("origin"), record.get("path"),
         int(bool(record.get("readable"))), record.get("thumbprint"), record.get("subject"),
         record.get("issuer"), record.get("cnpj"), record.get("not_after"),
         int(bool(record.get("has_private_key"))), record.get("file_sha256"),
         record.get("file_created"), record.get("zone_id"), record.get("host_url"),
         record.get("referrer_url"), verdict),
    )


def list_certificates(settings, host=None, only_flagged=True, collection_id=None) -> list[dict]:
    query, params = "SELECT * FROM certificates WHERE 1=1", []
    if only_flagged:
        query += " AND verdict != ''"
    if host:
        query += " AND host=?"
        params.append(host)
    if collection_id:
        query += " AND collection_id=?"
        params.append(collection_id)
    with connect(settings) as con:
        return [dict(r) for r in con.execute(query + " ORDER BY host, cnpj", params)]


def get_settings_overrides(settings) -> dict[str, str]:
    if not settings.db_path.exists():
        return {}
    with connect(settings) as con:
        try:
            return {r["key"]: r["value"] for r in con.execute("SELECT key, value FROM settings")}
        except sqlite3.OperationalError:
            return {}


def set_setting(settings, key: str, value: str | None) -> None:
    with connect(settings) as con:
        if value is None:
            con.execute("DELETE FROM settings WHERE key=?", (key,))
        else:
            con.execute("INSERT INTO settings (key, value) VALUES (?, ?)"
                        " ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def findings_for_triage(settings, min_score: int) -> list[dict]:
    with connect(settings) as con:
        return [dict(r) for r in con.execute(
            "SELECT * FROM findings WHERE score >= ? AND (triage_label IS NULL OR triage_label='erro')"
            " ORDER BY id", (min_score,))]


def list_cert_activity(settings, host=None, limit=5000, collection_id=None) -> list[dict]:
    query = ("SELECT e.*, (SELECT GROUP_CONCAT(f.rule_id) FROM findings f WHERE f.event_id=e.id)"
             " AS rule_ids, (SELECT MAX(f.score) FROM findings f WHERE f.event_id=e.id) AS score"
             " FROM events e WHERE e.category='certificado_atividade'")
    params: list = []
    if host:
        query += " AND e.host=?"
        params.append(host)
    if collection_id:
        query += " AND e.collection_id=?"
        params.append(collection_id)
    query += " ORDER BY e.ts, e.id LIMIT ?"
    params.append(limit)
    with connect(settings) as con:
        return [dict(r) for r in con.execute(query, params)]


STALE_MINUTES = 10
MAX_RUN_EVENTS = 500


def record_progress(settings, *, run_id, host, collector, version, step, status, percent, detail) -> None:
    now = datetime.now(timezone.utc).isoformat()
    finished = 1 if step in ("fim", "falha") else 0
    with connect(settings) as con:
        con.execute(
            "INSERT INTO runs (run_id, host, collector, version, started_at, updated_at, step, status,"
            " percent, detail, finished) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(run_id) DO UPDATE SET updated_at=excluded.updated_at, step=excluded.step,"
            " status=excluded.status, percent=MAX(runs.percent, excluded.percent),"
            " detail=excluded.detail, finished=MAX(runs.finished, excluded.finished),"
            " host=excluded.host, version=excluded.version",
            (run_id, host, collector, version, now, now, step, status, percent, detail, finished))
        count = con.execute("SELECT COUNT(*) FROM run_events WHERE run_id=?", (run_id,)).fetchone()[0]
        if count < MAX_RUN_EVENTS:
            con.execute("INSERT INTO run_events (run_id, at, step, status, percent, detail)"
                        " VALUES (?, ?, ?, ?, ?, ?)", (run_id, now, step, status, percent, detail))


def _run_state(row: dict) -> str:
    if row["finished"]:
        if row["step"] == "falha":
            return "falhou"
        return "concluido_com_erro" if row["status"] == "erro" else "concluido"
    updated = datetime.fromisoformat(row["updated_at"])
    if datetime.now(timezone.utc) - updated > timedelta(minutes=STALE_MINUTES):
        return "sem_sinal"
    return "em_andamento"


def list_runs(settings, limit=200) -> list[dict]:
    with connect(settings) as con:
        rows = [dict(r) for r in con.execute(
            "SELECT * FROM runs ORDER BY updated_at DESC LIMIT ?", (limit,))]
    for r in rows:
        r["state"] = _run_state(r)
    return rows


def get_run(settings, run_id: str) -> dict | None:
    with connect(settings) as con:
        row = con.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
    if not row:
        return None
    r = dict(row)
    r["state"] = _run_state(r)
    return r


def run_history(settings, run_id: str) -> list[dict]:
    with connect(settings) as con:
        return [dict(r) for r in con.execute(
            "SELECT * FROM run_events WHERE run_id=? ORDER BY id", (run_id,))]


def create_analysis(settings, scope_host: str = "") -> int:
    with connect(settings) as con:
        cur = con.execute("INSERT INTO analyses (scope_host, status, created_at) VALUES (?, 'pendente', ?)",
                          (scope_host or "", datetime.now(timezone.utc).isoformat()))
        return cur.lastrowid


def finish_analysis(settings, analysis_id: int, *, text: str, model: str, stats: dict) -> None:
    with connect(settings) as con:
        con.execute("UPDATE analyses SET status='concluida', finished_at=?, model=?, text=?, stats=?,"
                    " error=NULL WHERE id=?", (datetime.now(timezone.utc).isoformat(), model, text,
                                               json.dumps(stats), analysis_id))


def fail_analysis(settings, analysis_id: int, error: str) -> None:
    with connect(settings) as con:
        con.execute("UPDATE analyses SET status='erro', finished_at=?, error=? WHERE id=?",
                    (datetime.now(timezone.utc).isoformat(), error[:1000], analysis_id))


def get_analysis(settings, analysis_id: int) -> dict | None:
    with connect(settings) as con:
        row = con.execute("SELECT * FROM analyses WHERE id=?", (analysis_id,)).fetchone()
        return dict(row) if row else None


def list_analyses(settings, scope_host: str = "", limit: int = 20) -> list[dict]:
    with connect(settings) as con:
        return [dict(r) for r in con.execute(
            "SELECT * FROM analyses WHERE scope_host=? ORDER BY id DESC LIMIT ?", (scope_host or "", limit))]


def latest_analysis(settings, scope_host: str = "") -> dict | None:
    with connect(settings) as con:
        row = con.execute("SELECT * FROM analyses WHERE scope_host=? AND status='concluida'"
                          " ORDER BY id DESC LIMIT 1", (scope_host or "",)).fetchone()
        return dict(row) if row else None


def list_hosts(settings) -> list[str]:
    with connect(settings) as con:
        return [r[0] for r in con.execute("SELECT DISTINCT host FROM collections ORDER BY host")]


def set_file_note(con, collection_id: int, original_path: str, note: str) -> None:
    con.execute("UPDATE files SET note=? WHERE collection_id=? AND original_path=?",
                (note, collection_id, original_path))


def list_collection_files(settings, collection_id: int, category=None, q=None, status=None) -> list[dict]:
    query = ("SELECT f.*, f.note AS reason,"
             " (SELECT COUNT(*) FROM events e WHERE e.collection_id=f.collection_id"
             "  AND e.original_path=f.original_path) AS events,"
             " (SELECT COUNT(*) FROM findings x WHERE x.collection_id=f.collection_id"
             "  AND x.original_path=f.original_path) AS findings"
             " FROM files f WHERE f.collection_id=?")
    params: list = [collection_id]
    if category:
        query += " AND f.category=?"
        params.append(category)
    if status:
        query += " AND f.status=?"
        params.append(status)
    if q:
        query += " AND lower(f.original_path) LIKE ?"
        params.append(f"%{q.lower()}%")
    query += " ORDER BY f.category, f.original_path"
    with connect(settings) as con:
        return [dict(r) for r in con.execute(query, params)]


def collection_file(settings, collection_id: int, original_path: str) -> dict | None:
    rows = [r for r in list_collection_files(settings, collection_id) if r["original_path"] == original_path]
    return rows[0] if rows else None


def file_events(settings, collection_id: int, original_path: str, limit: int = 2000) -> list[dict]:
    with connect(settings) as con:
        return [dict(r) for r in con.execute(
            "SELECT * FROM events WHERE collection_id=? AND original_path=? ORDER BY id LIMIT ?",
            (collection_id, original_path, limit))]


def file_findings(settings, collection_id: int, original_path: str) -> list[dict]:
    with connect(settings) as con:
        return [dict(r) for r in con.execute(
            "SELECT * FROM findings WHERE collection_id=? AND original_path=? ORDER BY score DESC, id",
            (collection_id, original_path))]
