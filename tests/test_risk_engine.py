import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from app.services.risk_engine import RiskEngine

@pytest.fixture
def risk_engine():
    with patch("app.services.risk_engine.redis.from_url") as mock_redis:
        mock_redis_instance = AsyncMock()
        mock_redis.return_value = mock_redis_instance
        engine = RiskEngine()
        engine.domain_manager = AsyncMock()
        engine.domain_manager.is_disposable.return_value = False
        return engine

def test_entropy_calculation(risk_engine):
    # Low entropy
    assert risk_engine.calculate_entropy("john") < 3.0
    # High entropy (random)
    assert risk_engine.calculate_entropy("839210skw") > 3.0 

@pytest.mark.asyncio
async def test_analyze_high_risk_disposable(risk_engine):
    risk_engine.domain_manager.is_disposable.return_value = True
    # Mock check_mx_record to True so we isolate disposable check
    with patch.object(risk_engine, 'check_mx_record', new_callable=AsyncMock) as mock_mx:
        mock_mx.return_value = True
        # Mock velocity to False
        with patch.object(risk_engine, 'check_velocity', new_callable=AsyncMock) as mock_velocity:
            mock_velocity.return_value = False
            
            result = await risk_engine.analyze("user@yopmail.com", "1.1.1.1", "agent")
            
            assert result["risk_summary"]["level"] == "HIGH"
            assert result["signals"]["is_disposable"] is True
            assert result["risk_summary"]["score"] >= 90

@pytest.mark.asyncio
async def test_analyze_no_mx(risk_engine):
    risk_engine.domain_manager.is_disposable.return_value = False
    with patch.object(risk_engine, 'check_mx_record', new_callable=AsyncMock) as mock_mx:
        mock_mx.return_value = False
        with patch.object(risk_engine, 'check_velocity', new_callable=AsyncMock) as mock_vel:
            mock_vel.return_value = False
            
            result = await risk_engine.analyze("user@invalid.com", "1.1.1.1", "agent")
            
            assert result["risk_summary"]["level"] == "HIGH"
            assert result["signals"]["mx_found"] is False
            assert result["risk_summary"]["score"] >= 100
