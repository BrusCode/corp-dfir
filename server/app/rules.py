"""Deterministic detection: YAML rules applied to event text."""

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from app.masking import fingerprint, mask

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
SEVERITY_SCORE = {"baixa": 1, "media": 3, "alta": 5}
CONTEXT_WINDOW = 40
SNIPPET_RADIUS = 80


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    pattern: re.Pattern
    secret: bool = False
    context: re.Pattern | None = None


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: str
    score: int
    snippet: str
    masked: str | None = None
    fingerprint: str | None = None


def load_rules(rules_dir: Path = RULES_DIR) -> list[Rule]:
    rules = []
    for path in sorted(rules_dir.glob("*.yaml")):
        for raw in yaml.safe_load(path.read_text(encoding="utf-8")) or []:
            rules.append(
                Rule(
                    id=raw["id"],
                    category=raw["category"],
                    severity=raw["severity"],
                    pattern=re.compile(raw["pattern"]),
                    secret=bool(raw.get("secret", False)),
                    context=re.compile(raw["context"]) if raw.get("context") else None,
                )
            )
    return rules


def _snippet(text: str, start: int, end: int, replacement: str | None) -> str:
    before = text[max(0, start - SNIPPET_RADIUS) : start]
    after = text[end : end + SNIPPET_RADIUS]
    middle = replacement if replacement is not None else text[start:end]
    return f"{before}{middle}{after}".replace("\n", " ").strip()


def scan_text(text: str, rules: list[Rule]) -> list[Finding]:
    if not text:
        return []
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for rule in rules:
        for match in rule.pattern.finditer(text):
            start, end = match.span()
            if rule.context:
                window = text[max(0, start - CONTEXT_WINDOW) : start]
                if not rule.context.search(window):
                    continue
            key = (rule.id, start)
            if key in seen:
                continue
            seen.add(key)
            value = match.group(0)
            masked = mask(value) if rule.secret else None
            findings.append(
                Finding(
                    rule_id=rule.id,
                    category=rule.category,
                    severity=rule.severity,
                    score=SEVERITY_SCORE[rule.severity],
                    snippet=_snippet(text, start, end, masked),
                    masked=masked,
                    fingerprint=fingerprint(value) if rule.secret else None,
                )
            )
    return findings


def mask_secrets(text: str, rules: list[Rule]) -> str:
    """Return text with every secret replaced by its mask (used before the LLM)."""
    for rule in rules:
        if rule.secret:
            text = rule.pattern.sub(lambda m: mask(m.group(0)), text)
    return text
