"""Display times in Brasília time (UTC-3); data stays stored in UTC."""

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

BRT = ZoneInfo("America/Sao_Paulo")


def br_datetime(value, seconds: bool = True) -> str:
    if not value:
        return ""
    text = str(value).strip()
    try:
        iso = text.replace("Z", "+00:00")
        # Windows writes 7 fractional digits; Python accepts at most 6.
        if "." in iso:
            head, frac = iso.split(".", 1)
            digits = "".join(ch for ch in frac if ch.isdigit())
            rest = frac[len(digits):]
            iso = f"{head}.{digits[:6]}{rest}"
        dt = datetime.fromisoformat(iso.replace(" ", "T", 1))
    except ValueError:
        return text
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(BRT).strftime("%d/%m/%Y %H:%M:%S" if seconds else "%d/%m/%Y %H:%M")
