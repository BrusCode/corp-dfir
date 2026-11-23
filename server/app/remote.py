"""Remote access log lines: keep sessions and file transfers, drop service noise."""

import re

SESSION = re.compile(
    r"(?i)incoming session|session request|accepting from|connection opened|incoming connection|"
    r"new connection|login from|connected from|remote control session|authenticat\w* (succe|ok)|"
    r"addparticipant|participant (added|joined)")
TRANSFER = re.compile(r"(?i)file ?transfer|send(ing)? file|receiv(e|ing) file|file (sent|received)")
CLOSED = re.compile(r"(?i)session (closed|ended)|connection closed|disconnected from peer")
OURS = {"webposto-agente"}


def is_relevant(line: str) -> bool:
    return bool(SESSION.search(line) or TRANSFER.search(line) or CLOSED.search(line))


def classify_remote_line(source: str, line: str) -> tuple[str, str] | None:
    """(rule_id, severity) for a remote access log line, or None when it is not a finding."""
    if TRANSFER.search(line):
        return "acesso_remoto_arquivo", "media"
    if SESSION.search(line):
        return "acesso_remoto_sessao", "baixa"
    return None


def tool_label(source: str) -> str:
    return f"{source} (nosso)" if source in OURS else source
