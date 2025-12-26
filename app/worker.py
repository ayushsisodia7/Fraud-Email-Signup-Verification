from __future__ import annotations

import asyncio
import json

import redis.asyncio as redis

from app.core.config import settings
from app.core.logging import setup_logging, get_logger
from app.core.metrics import ENRICHMENT_JOBS_TOTAL
from app.services.risk_engine import RiskEngine
from app.services.enrichment_queue import store_result

logger = get_logger("worker")


async def run_worker():
    setup_logging()
    logger.info("Starting enrichment worker...")

    redis_client = redis.from_url(
        f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}",
        encoding="utf-8",
        decode_responses=True,
    )

    engine = RiskEngine()

    try:
        while True:
            # BRPOP returns (key, value)
            item = await redis_client.brpop(settings.ENRICHMENT_QUEUE_KEY, timeout=5)
            if not item:
                continue
            _, raw = item

            try:
                job = json.loads(raw)
                job_id = job["job_id"]
                email = job["email"]
                ip_address = job["ip_address"]
                user_agent = job["user_agent"]
                ENRICHMENT_JOBS_TOTAL.labels(event="started").inc()

                # Full analysis (may be slow)
                result = await engine.analyze(email, ip_address, user_agent)
                result["enrichment"] = {"job_id": job_id, "status": "COMPLETE"}
                await store_result(redis_client, job_id, result)
                ENRICHMENT_JOBS_TOTAL.labels(event="succeeded").inc()
            except Exception as e:
                logger.exception(f"Worker failed processing job: {e}")
                ENRICHMENT_JOBS_TOTAL.labels(event="failed").inc()
    finally:
        await engine.close()
        await redis_client.close()


def main():
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()


