import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, MagicMock

from main import app
from app.api.v1.endpoints import set_risk_engine
from app.core.config import settings
from tests.fake_redis import AsyncFakeRedis
from app.services.enrichment_queue import get_result


@pytest.mark.asyncio
async def test_analyze_fast_enqueues_and_stores_base_result():
    old = settings.ENABLE_BACKGROUND_ENRICHMENT
    settings.ENABLE_BACKGROUND_ENRICHMENT = True
    try:
        fake_redis = AsyncFakeRedis()
        mock_engine = MagicMock()
        mock_engine.redis = fake_redis
        mock_engine.analyze_fast = AsyncMock(return_value={
            "email": "test@example.com",
            "normalized_email": "test@example.com",
            "reasons": [],
            "risk_summary": {"score": 0, "level": "LOW", "action": "ALLOW"},
            "signals": {"mx_found": True, "is_disposable": False, "entropy_score": 0.0, "velocity_breach": None,
                        "is_alias": False, "is_vpn": None, "is_proxy": None, "is_datacenter": None,
                        "ip_country": None, "domain_age_days": None, "is_new_domain": None,
                        "pattern_detected": None, "is_sequential": None, "has_number_suffix": None,
                        "is_similar_to_recent": None, "smtp_deliverable": None, "smtp_valid": None,
                        "catch_all_domain": None}
        })

        set_risk_engine(mock_engine)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.post("/api/v1/analyze/fast", json={
                "email": "test@example.com",
                "ip_address": "1.2.3.4",
                "user_agent": "ua"
            })

        assert resp.status_code == 200
        data = resp.json()
        assert data["enrichment"]["status"] == "PENDING"
        job_id = data["enrichment"]["job_id"]
        assert job_id

        stored = await get_result(fake_redis, job_id)
        assert stored is not None
        assert stored["email"] == "test@example.com"
        assert stored["enrichment"]["job_id"] == job_id
    finally:
        settings.ENABLE_BACKGROUND_ENRICHMENT = old


