import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, MagicMock
from main import app
from app.api.v1.endpoints import set_risk_engine

@pytest.fixture
def mock_risk_engine():
    mock_engine = MagicMock()
    mock_engine.analyze = AsyncMock(return_value={
        "email": "test@example.com",
        "normalized_email": "test@example.com",
        "risk_summary": {
            "score": 0,
            "level": "LOW",
            "action": "ALLOW"
        },
        "signals": {
            "is_disposable": False,
            "mx_found": True,
            "velocity_breach": False,
            "entropy_score": 0.0
        }
    })
    # We need to simulate the dependency injection
    set_risk_engine(mock_engine)
    return mock_engine

@pytest.mark.asyncio
async def test_analyze_endpoint(mock_risk_engine):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.post("/api/v1/analyze", json={
            "email": "test@example.com",
            "ip_address": "127.0.0.1",
            "user_agent": "test-agent"
        })
    
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "test@example.com"
    assert data["risk_summary"]["action"] == "ALLOW"
    mock_risk_engine.analyze.assert_called_once()

@pytest.mark.asyncio
async def test_analyze_invalid_email(mock_risk_engine):
    # Mocking exceptions raised by RiskEngine
    mock_risk_engine.analyze.side_effect = ValueError("Invalid email format")
    
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.post("/api/v1/analyze", json={
            "email": "invalid-email",
            "ip_address": "127.0.0.1",
            "user_agent": "test-agent"
        })
    
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid email format"
