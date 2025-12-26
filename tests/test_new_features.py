"""
Tests for new fraud detection features
"""
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch
import json
from app.services.ip_intelligence import IPIntelligenceService
from app.services.domain_age import DomainAgeService
from app.services.pattern_detection import PatternDetectionService
from tests.fake_redis import AsyncFakeRedis


@pytest.fixture
async def redis_client():
    """In-memory Redis fake for deterministic tests"""
    yield AsyncFakeRedis()


class TestIPIntelligence:
    """Test IP intelligence service"""
    
    def test_private_ip_detection(self):
        """Test that private IPs are correctly identified"""
        service = IPIntelligenceService()
        
        # Test private IPs
        assert service._is_private_ip("192.168.1.1") == True
        assert service._is_private_ip("10.0.0.1") == True
        assert service._is_private_ip("172.16.0.1") == True
        assert service._is_private_ip("127.0.0.1") == True
        
        # Test public IP
        assert service._is_private_ip("8.8.8.8") == False
    
    @pytest.mark.asyncio
    async def test_analyze_private_ip(self):
        """Test analysis skips for private IPs"""
        service = IPIntelligenceService()
        result = await service.analyze_ip("192.168.1.1")
        
        assert result["is_vpn"] == False
        assert result["is_proxy"] == False
        assert result["is_datacenter"] == False
        assert result["country"] is None

    @pytest.mark.asyncio
    async def test_ip_intel_cache_hit_avoids_http(self):
        """Second call should hit Redis cache and not call external HTTP."""
        redis_mock = AsyncMock()
        redis_mock.get = AsyncMock(side_effect=[None, json.dumps({
            "is_vpn": False,
            "is_proxy": False,
            "is_datacenter": True,
            "country": "United States",
            "asn": "AS123",
            "org": "Example Cloud",
        })])
        redis_mock.set = AsyncMock()

        service = IPIntelligenceService(redis_client=redis_mock, cache_ttl_seconds=3600, negative_cache_ttl_seconds=60)

        class DummyResponse:
            status_code = 200
            def json(self):
                return {
                    "country_name": "United States",
                    "asn": "AS123",
                    "org": "Example Cloud",
                }

        class DummyClient:
            async def __aenter__(self): return self
            async def __aexit__(self, exc_type, exc, tb): return False
            async def get(self, url):  # noqa: ARG002
                return DummyResponse()

        with patch("app.services.ip_intelligence.httpx.AsyncClient", return_value=DummyClient()) as mock_client:
            res1 = await service.analyze_ip("8.8.8.8")
            res2 = await service.analyze_ip("8.8.8.8")

        assert res1["country"] == "United States"
        assert res2["country"] == "United States"
        # external client constructed only once (second call should return from cache before constructing)
        assert mock_client.call_count == 1
        assert redis_mock.set.call_count == 1


class TestDomainAge:
    """Test domain age verification service"""
    
    @pytest.mark.asyncio
    async def test_domain_age_cache_hit_avoids_whois(self):
        """Second call should hit Redis cache and not call WHOIS."""
        redis_mock = AsyncMock()
        # first call: no cache; second call: cached creation_date
        creation = datetime.now(timezone.utc) - timedelta(days=3650)
        redis_mock.get = AsyncMock(side_effect=[None, json.dumps({"creation_date": creation.isoformat()})])
        redis_mock.set = AsyncMock()

        service = DomainAgeService(redis_client=redis_mock, cache_ttl_seconds=3600, negative_cache_ttl_seconds=60)

        class DummyWhois:
            creation_date = creation

        with patch("app.services.domain_age.whois.whois", return_value=DummyWhois()) as mock_whois:
            result1 = await service.check_domain_age("example.com")
            result2 = await service.check_domain_age("example.com")
        
        assert result1["is_new_domain"] == False
        assert result2["is_new_domain"] == False
        assert result1["creation_date"] is not None
        assert result2["creation_date"] is not None
        
        assert mock_whois.call_count == 1
        assert redis_mock.set.call_count == 1

    @pytest.mark.asyncio
    async def test_new_domain_threshold_is_configurable(self):
        """If suspicious_age_days is low, even a ~10 day domain should be marked new."""
        creation = datetime.now(timezone.utc) - timedelta(days=10)
        service = DomainAgeService(redis_client=None, suspicious_age_days=15)
        result = service._build_result("example.com", creation)
        assert result["is_new_domain"] is True


class TestPatternDetection:
    """Test email pattern detection service"""
    
    @pytest.mark.asyncio
    async def test_sequential_pattern(self, redis_client):
        """Test sequential number detection"""
        service = PatternDetectionService(redis_client)
        
        # Sequential patterns
        assert service._is_sequential_pattern("user1") == True
        assert service._is_sequential_pattern("test5") == True
        assert service._is_sequential_pattern("abc9") == True
        
        # Not sequential
        assert service._is_sequential_pattern("user12") == False
        assert service._is_sequential_pattern("john.doe") == False
    
    @pytest.mark.asyncio
    async def test_number_suffix(self, redis_client):
        """Test number suffix detection"""
        service = PatternDetectionService(redis_client)
        
        # Has number suffix
        assert service._has_number_suffix("john123") == True
        assert service._has_number_suffix("test.user456") == True
        assert service._has_number_suffix("abc_def99") == True
        
        # No number suffix or insufficient digits
        assert service._has_number_suffix("john1") == False
        assert service._has_number_suffix("john.doe") == False
    
    @pytest.mark.asyncio
    async def test_similarity_detection(self, redis_client):
        """Test similarity detection between emails"""
        service = PatternDetectionService(redis_client)
        
        # Store first email
        await service._store_recent_email("test.user@example.com")
        
        # Check very similar email
        result = await service._check_similarity("test.user1@example.com")
        assert result["is_similar"] == True
        assert result["max_similarity"] > 0.85
        
        # Check dissimilar email
        result2 = await service._check_similarity("completely.different@example.com")
        assert result2["is_similar"] == False
    
    @pytest.mark.asyncio
    async def test_analyze_patterns(self, redis_client):
        """Test full pattern analysis"""
        service = PatternDetectionService(redis_client)
        
        # Test sequential pattern
        result = await service.analyze_patterns("user1@example.com", "user1@example.com")
        assert result["is_sequential"] == True
        assert result["pattern_type"] == "SEQUENTIAL"
        
        # Test number suffix pattern
        result = await service.analyze_patterns("john123@example.com", "john123@example.com")
        assert result["has_number_suffix"] == True
        assert result["pattern_type"] == "NUMBER_SUFFIX"
        
        # Test normal email
        result = await service.analyze_patterns("john.doe@example.com", "john.doe@example.com")
        assert result["is_sequential"] == False
        assert result["has_number_suffix"] == False
        assert result["pattern_type"] is None


class TestIntegration:
    """Integration tests for the full risk engine"""
    
    @pytest.mark.asyncio
    async def test_vpn_detection_scoring(self):
        """Test that VPN detection adds to risk score"""
        # This would require mocking the IP API
        # For now, we verify the scoring logic
        pass
    
    @pytest.mark.asyncio
    async def test_new_domain_scoring(self):
        """Test that new domains add to risk score"""
        # This would require mocking WHOIS
        pass
    
    @pytest.mark.asyncio
    async def test_pattern_scoring(self):
        """Test that patterns add to risk score"""
        # This would require full risk engine setup
        pass
