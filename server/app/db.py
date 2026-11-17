"""SQLite storage: collections (custody), files (manifest), events and findings."""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

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


def init_db(settings: Settings) -> None:
    for path in (settings.data_dir, settings.evidence_dir, settings.work_dir):
        path.mkdir(parents=True, exist_ok=True)
    with connect(settings) as con:
        con.executescript(SCHEMA)


def create_collection(settings, *, host, filename, sha256, stored_path, custody) -> int:
    with connect(settings) as con:
        cur = con.execute(
            "INSERT INTO collections (host, filename, sha256, stored_path, custody, received_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (host, filename, sha256, stored_path, json.dumps(custody),
             datetime.now(timezone.utc).isoformat()),
        )
        return cur.lastrowid


def set_status(settings, collection_id: int, status: str, error: str | None = None) -> None:
    with connect(settings) as con:
        con.execute("UPDATE collections SET status=?, error=? WHERE id=?",
                    (status, error, collection_id))


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


def remote_events(settings, host=None) -> list[dict]:
    query = "SELECT * FROM events WHERE category='acesso_remoto'"
    params = []
    if host:
        query += " AND host=?"
        params.append(host)
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
