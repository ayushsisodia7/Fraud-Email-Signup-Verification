import pytest
from httpx import AsyncClient, ASGITransport

from main import app


@pytest.mark.asyncio
async def test_request_id_is_returned():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/")
    assert resp.status_code == 200
    assert "X-Request-ID" in resp.headers


@pytest.mark.asyncio
async def test_request_id_is_propagated_when_provided():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/", headers={"X-Request-ID": "req-123"})
    assert resp.status_code == 200
    assert resp.headers.get("X-Request-ID") == "req-123"


