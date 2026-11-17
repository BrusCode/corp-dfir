"""Masking and fingerprinting of secrets: the full value never leaves the evidence."""

import hashlib

PREFIX_LEN = 6
TAIL_LEN = 4


def mask(value: str) -> str:
    """Keep a short prefix (secret type) and the last characters (identification)."""
    if len(value) <= PREFIX_LEN + TAIL_LEN + 4:
        return "…"
    return f"{value[:PREFIX_LEN]}…{value[-TAIL_LEN:]}"


def fingerprint(value: str) -> str:
    """Stable identifier to correlate the same secret across hosts without showing it."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
