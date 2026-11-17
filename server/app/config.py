"""Settings from environment variables (populated by deploy/.env)."""

import os
from dataclasses import dataclass
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
    )
