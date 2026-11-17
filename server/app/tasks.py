"""Taskiq broker (Redis) and the processing task run by the worker."""

from taskiq_redis import ListQueueBroker

from app import db
from app.config import get_settings
from app.pipeline import process_bundle

broker = ListQueueBroker(url=get_settings().redis_url)


@broker.task(task_name="process_upload", retry_on_error=False)
def process_upload(collection_id: int) -> dict:
    settings = get_settings()
    db.init_db(settings)
    return process_bundle(settings, collection_id)
