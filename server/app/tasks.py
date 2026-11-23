"""Taskiq broker (Redis) and the processing task run by the worker."""

from taskiq_redis import ListQueueBroker

from app import analysis, db
from app.config import get_settings
from app.pipeline import process_bundle, retriage_pending

broker = ListQueueBroker(url=get_settings().redis_url)


@broker.task(task_name="process_upload", retry_on_error=False)
def process_upload(collection_id: int) -> dict:
    settings = get_settings()
    db.init_db(settings)
    return process_bundle(settings, collection_id)


@broker.task(task_name="retriage", retry_on_error=False)
def retriage() -> int:
    settings = get_settings()
    db.init_db(settings)
    return retriage_pending(settings)


@broker.task(task_name="run_analysis", retry_on_error=False)
def run_analysis(analysis_id: int) -> None:
    settings = get_settings()
    db.init_db(settings)
    analysis.run_analysis(settings, analysis_id)
