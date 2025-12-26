import pytest
from httpx import AsyncClient, ASGITransport

from main import app
from app.core.config import settings


@pytest.mark.asyncio
async def test_admin_endpoints_unprotected_when_key_not_set():
    old = settings.ADMIN_API_KEY
    old_env = settings.ENVIRONMENT
    settings.ADMIN_API_KEY = ""
    settings.ENVIRONMENT = "dev"
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/api/v1/admin/health")
        # Auth is disabled if ADMIN_API_KEY is empty
        assert resp.status_code in (200, 500)
    finally:
        settings.ADMIN_API_KEY = old
        settings.ENVIRONMENT = old_env


@pytest.mark.asyncio
async def test_admin_endpoints_require_key_when_set():
    old = settings.ADMIN_API_KEY
    old_env = settings.ENVIRONMENT
    settings.ADMIN_API_KEY = "secret"
    settings.ENVIRONMENT = "dev"
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            no_key = await ac.get("/api/v1/admin/health")
            bad_key = await ac.get("/api/v1/admin/health", headers={"X-Admin-API-Key": "wrong"})
            good_key = await ac.get("/api/v1/admin/health", headers={"X-Admin-API-Key": "secret"})

        assert no_key.status_code == 401
        assert bad_key.status_code == 401
        # Success depends on redis availability, but auth must pass
        assert good_key.status_code in (200, 500)
    finally:
        settings.ADMIN_API_KEY = old
        settings.ENVIRONMENT = old_env


