from __future__ import annotations

import json
from uuid import uuid4
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger
from app.core.metrics import ENRICHMENT_JOBS_TOTAL

logger = get_logger(__name__)


def _result_key(job_id: str) -> str:
    return f"{settings.ENRICHMENT_RESULT_PREFIX}{job_id}"


async def enqueue_job(redis_client, payload: dict[str, Any]) -> str:
    job_id = str(uuid4())
    payload_with_id = {"job_id": job_id, **payload}
    await redis_client.lpush(settings.ENRICHMENT_QUEUE_KEY, json.dumps(payload_with_id))
    ENRICHMENT_JOBS_TOTAL.labels(event="enqueued").inc()
    return job_id


async def store_result(redis_client, job_id: str, result: dict[str, Any]) -> None:
    key = _result_key(job_id)
    await redis_client.set(key, json.dumps(result), ex=settings.ENRICHMENT_RESULT_TTL_SECONDS)


async def get_result(redis_client, job_id: str) -> dict[str, Any] | None:
    key = _result_key(job_id)
    raw = await redis_client.get(key)
    if not raw:
        return None
    return json.loads(raw)


