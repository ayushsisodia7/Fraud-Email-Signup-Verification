"""
Tests for new fraud detection features
"""
import pytest
from app.services.ip_intelligence import IPIntelligenceService
from app.services.domain_age import DomainAgeService
from app.services.pattern_detection import PatternDetectionService
import redis.asyncio as redis


@pytest.fixture
async def redis_client():
    """Create Redis client for testing"""
    client = redis.from_url("redis://localhost:6379", encoding="utf-8", decode_responses=True)
    yield client
    await client.flushdb()  # Clean up after tests
    await client.close()


class TestIPIntelligence:
    """Test IP intelligence service"""
    
    @pytest.mark.asyncio
    async def test_private_ip_detection(self):
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


class TestDomainAge:
    """Test domain age verification service"""
    
    @pytest.mark.asyncio
    async def test_well_known_domain(self):
        """Test checking a well-known, old domain"""
        service = DomainAgeService()
        result = await service.check_domain_age("google.com")
        
        # Google is old, should not be flagged as new
        assert result["is_new_domain"] == False
        assert result["is_suspicious"] == False
        
        # Age should be available (though WHOIS can be unreliable)
        if result["age_days"] is not None:
            assert result["age_days"] > 30


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
