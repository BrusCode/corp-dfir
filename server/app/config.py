"""Settings from environment variables (populated by deploy/.env)."""

import os
import re
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    upload_token: str
    redis_url: str
    llm_base_url: str
    llm_api_key: str
    llm_model: str
    llm_min_score: int
    max_upload_bytes: int
    own_cnpjs: frozenset
    company_context: str = ""
    scripts_dir: Path = Path("/collector")
    server_cert: Path = Path("/certs/server.crt")

    @property
    def db_path(self) -> Path:
        return self.data_dir / "dfir.sqlite3"

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @property
    def work_dir(self) -> Path:
        return self.data_dir / "work"


@lru_cache
def get_settings() -> Settings:
    data_dir = Path(os.environ.get("DFIR_DATA_DIR", "/data"))
    return Settings(
        data_dir=data_dir,
        upload_token=os.environ.get("DFIR_UPLOAD_TOKEN", ""),
        redis_url=os.environ.get("REDIS_URL", "redis://redis:6379/0"),
        llm_base_url=os.environ.get("LLM_BASE_URL", "").rstrip("/"),
        llm_api_key=os.environ.get("LLM_API_KEY", ""),
        llm_model=os.environ.get("LLM_MODEL", ""),
        llm_min_score=int(os.environ.get("LLM_MIN_SCORE", "5")),
        max_upload_bytes=int(os.environ.get("DFIR_MAX_UPLOAD_BYTES", str(2_200 * 1024 * 1024))),
        own_cnpjs=parse_cnpjs(os.environ.get("DFIR_OWN_CNPJS", "")),
        scripts_dir=Path(os.environ.get("DFIR_SCRIPTS_DIR", "/collector")),
        server_cert=Path(os.environ.get("DFIR_SERVER_CERT", "/certs/server.crt")),
    )


def parse_cnpjs(raw: str) -> frozenset:
    return frozenset(d for d in (re.sub(r"\D", "", c) for c in raw.split(",")) if d)


def effective(settings: Settings) -> Settings:
    """Environment settings overridden by what was saved in the admin page."""
    from app import db

    o = db.get_settings_overrides(settings)
    changes = {}
    if "own_cnpjs" in o:
        changes["own_cnpjs"] = parse_cnpjs(o["own_cnpjs"])
    for key in ("llm_base_url", "llm_api_key", "llm_model"):
        if key in o:
            changes[key] = o[key].rstrip("/") if key == "llm_base_url" else o[key]
    if "company_context" in o:
        changes["company_context"] = o["company_context"]
    if o.get("llm_min_score", "").isdigit():
        changes["llm_min_score"] = int(o["llm_min_score"])
    return replace(settings, **changes)
