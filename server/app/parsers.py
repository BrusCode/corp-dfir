"""Turn collected files into normalized events (text + metadata)."""

import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

MAX_TEXT_BYTES = 50 * 1024 * 1024
MIN_STRING_LEN = 3
# Keys of VS Code-family state.vscdb that hold chat/agent data.
VSCDB_KEY_HINTS = re.compile(
    r"(?i)chat|aichat|composer|copilot|cline|roo|continue|agent|conversation|prompt|history"
)
REMOTE_LINE = re.compile(
    r"(?i)incoming|outgoing|connect|session|login|auth|accepted|peer|from \d{1,3}(?:\.\d{1,3}){3}"
)


@dataclass
class Event:
    source: str
    text: str
    role: str | None = None
    ts: str | None = None
    location: str | None = None


def _strings(node, out: list[str]) -> None:
    if isinstance(node, str):
        if len(node) >= MIN_STRING_LEN:
            out.append(node)
    elif isinstance(node, dict):
        for value in node.values():
            _strings(value, out)
    elif isinstance(node, list):
        for value in node:
            _strings(value, out)


def _message_text(obj: dict) -> str:
    message = obj.get("message") if isinstance(obj.get("message"), dict) else obj
    content = message.get("content", message.get("text"))
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        blocks = [b for b in content if isinstance(b, dict)]
        texts = [str(b.get("text") or b.get("input") or b.get("content") or "") for b in blocks]
        if any(texts):
            return "\n".join(t for t in texts if t)
    parts: list[str] = []
    _strings(content if content is not None else obj, parts)
    return "\n".join(parts)


def _role(obj: dict) -> str | None:
    message = obj.get("message") if isinstance(obj.get("message"), dict) else {}
    return message.get("role") or obj.get("role") or obj.get("type")


def _ts(obj: dict) -> str | None:
    for key in ("timestamp", "ts", "created_at", "createdAt", "time"):
        if obj.get(key):
            return str(obj[key])
    return None


def _source_for(path: Path) -> str:
    p = str(path).lower()
    for name in ("anydesk", "teamviewer", "rustdesk", "claude", "codex", "gemini",
                 "antigravity", "cursor", "windsurf", "continue", "aider", "openai",
                 "chatgpt", "code", "psreadline"):
        if name in p:
            return name
    if path.name.lower().startswith("connection") or path.suffix.lower() == ".trace":
        return "anydesk"
    return "arquivo"


def _parse_jsonl(path: Path, source: str) -> list[Event]:
    events = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            text = _message_text(obj)
            if text:
                events.append(Event(source, text, _role(obj), _ts(obj), f"{path.name}:{n}"))
    return events


def _parse_json(path: Path, source: str) -> list[Event]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return _parse_text(path, source)
    out: list[str] = []
    _strings(data, out)
    return [Event(source, s, location=path.name) for s in out]


def _parse_vscdb(path: Path, source: str) -> list[Event]:
    events = []
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            rows = con.execute("SELECT key, value FROM ItemTable").fetchall()
        finally:
            con.close()
    except sqlite3.Error:
        return []
    for key, value in rows:
        if not VSCDB_KEY_HINTS.search(str(key)):
            continue
        raw = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
        try:
            out: list[str] = []
            _strings(json.loads(raw), out)
        except json.JSONDecodeError:
            out = [raw]
        events.extend(Event(source, s, location=f"{path.name}:{key}") for s in out)
    return events


def _parse_text(path: Path, source: str) -> list[Event]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return [Event(source, text, location=path.name)] if text.strip() else []


def _parse_remote(path: Path, source: str) -> list[Event]:
    events = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            # Connection files list one session per line; logs keep only connection lines.
            is_connection_file = path.name.lower().startswith("connection")
            if is_connection_file or REMOTE_LINE.search(line):
                events.append(Event(source, line, location=f"{path.name}:{n}"))
    return events


def _is_text(path: Path) -> bool:
    with path.open("rb") as fh:
        return b"\x00" not in fh.read(4096)


def parse_file(path: Path, category: str) -> list[Event]:
    if not path.is_file() or path.stat().st_size > MAX_TEXT_BYTES:
        return []
    source = _source_for(path)
    name = path.name.lower()
    suffix = path.suffix.lower()
    if suffix == ".vscdb":
        return _parse_vscdb(path, source)
    if not _is_text(path):
        return []
    if category == "acesso_remoto":
        return _parse_remote(path, source)
    if suffix == ".jsonl":
        return _parse_jsonl(path, source)
    if suffix == ".json":
        return _parse_json(path, source)
    if suffix in {".txt", ".log", ".md", ".env", ".toml", ".yaml", ".yml", ".ini",
                  ".cfg", ".conf", ".gitconfig", ".npmrc", ""} or name.startswith(".env") \
            or name.endswith("history"):
        return _parse_text(path, source)
    return []
