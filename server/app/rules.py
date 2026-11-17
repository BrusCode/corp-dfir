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


def _window(text: str, start: int, end: int) -> str:
    return text[max(0, start - SNIPPET_RADIUS) : end + SNIPPET_RADIUS].replace("\n", " ").strip()


def scan_text(text: str, rules: list[Rule]) -> list[Finding]:
    """Detect on the raw text, but always cut snippets from the masked text.

    A snippet of any finding (secret or keyword) may contain a neighbor secret, so
    snippets never come from the raw text.
    """
    if not text:
        return []
    masked_text = mask_secrets(text, rules)
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for rule in rules:
        source = text if rule.secret else masked_text
        for match in rule.pattern.finditer(source):
            start, end = match.span()
            if rule.context:
                window = source[max(0, start - CONTEXT_WINDOW) : start]
                if not rule.context.search(window):
                    continue
            if (rule.id, start) in seen:
                continue
            seen.add((rule.id, start))
            if rule.secret:
                value = match.group(0)
                masked = mask(value)
                pos = masked_text.find(masked)
                snippet = _window(masked_text, max(pos, 0), max(pos, 0) + len(masked))
                findings.append(Finding(rule.id, rule.category, rule.severity,
                                        SEVERITY_SCORE[rule.severity], snippet,
                                        masked, fingerprint(value)))
            else:
                findings.append(Finding(rule.id, rule.category, rule.severity,
                                        SEVERITY_SCORE[rule.severity],
                                        _window(masked_text, start, end)))
    return findings


def mask_secrets(text: str, rules: list[Rule]) -> str:
    """Return text with every secret replaced by its mask (used before the LLM)."""
    for rule in rules:
        if rule.secret:
            text = rule.pattern.sub(lambda m: mask(m.group(0)), text)
    return text
