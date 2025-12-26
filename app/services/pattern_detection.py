"""
Email Pattern Detection Service
"""
import re
from typing import List, Optional
import Levenshtein
import redis.asyncio as redis
from app.core.logging import get_logger

logger = get_logger(__name__)

class PatternDetectionService:
    """Service to detect suspicious email patterns and similarities"""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.similarity_threshold = 0.85  # 85% similarity triggers a flag
        self.recent_emails_key = "pattern:recent_emails"
        self.recent_emails_ttl = 3600  # Keep recent emails for 1 hour
        
    async def analyze_patterns(self, email: str, normalized_email: str) -> dict:
        """
        Analyze email for suspicious patterns
        
        Returns:
            dict with keys:
                - is_sequential: bool (e.g., user1@, user2@)
                - has_number_suffix: bool (e.g., john.doe123@)
                - is_similar_to_recent: bool
                - similarity_score: float (0-1)
                - pattern_type: str or None
        """
        result = {
            "is_sequential": False,
            "has_number_suffix": False,
            "is_similar_to_recent": False,
            "similarity_score": 0.0,
            "pattern_type": None
        }
        
        local_part = email.split("@")[0]
        
        # Check for sequential patterns
        result["is_sequential"] = self._is_sequential_pattern(local_part)
        
        # Check for number suffix pattern (common in fraud)
        result["has_number_suffix"] = self._has_number_suffix(local_part)
        
        # Check similarity to recent signups
        try:
            similarity_result = await self._check_similarity(normalized_email)
            result["is_similar_to_recent"] = similarity_result["is_similar"]
            result["similarity_score"] = similarity_result["max_similarity"]
            
            # Store this email for future comparisons
            await self._store_recent_email(normalized_email)
            
        except Exception as e:
            logger.error(f"Error checking email similarity: {e}")
        
        # Determine pattern type
        if result["is_sequential"]:
            result["pattern_type"] = "SEQUENTIAL"
        elif result["has_number_suffix"]:
            result["pattern_type"] = "NUMBER_SUFFIX"
        elif result["is_similar_to_recent"]:
            result["pattern_type"] = "SIMILAR_TO_RECENT"
        
        if result["pattern_type"]:
            logger.info(f"Suspicious pattern detected in {email}: {result['pattern_type']}")
        
        return result
    
    def _is_sequential_pattern(self, local_part: str) -> bool:
        """
        Check if email follows sequential pattern like:
        user1, user2, test1, test2, etc.
        """
        # Pattern: word followed by a single digit
        pattern = re.compile(r'^[a-z]+[0-9]$', re.IGNORECASE)
        return bool(pattern.match(local_part))
    
    def _has_number_suffix(self, local_part: str) -> bool:
        """
        Check if email has numbers at the end (common fraud pattern)
        e.g., john.doe123, testuser456
        """
        # Remove common separators first
        clean = local_part.replace(".", "").replace("_", "").replace("-", "")
        
        # Check if ends with 2+ digits
        pattern = re.compile(r'[a-z]+[0-9]{2,}$', re.IGNORECASE)
        return bool(pattern.match(clean))
    
    async def _check_similarity(self, email: str) -> dict:
        """
        Check if this email is similar to recent signups using Levenshtein distance
        """
        try:
            # Get recent emails from Redis
            recent_emails = await self.redis.lrange(self.recent_emails_key, 0, 99)  # Check last 100
            
            max_similarity = 0.0
            is_similar = False
            
            for recent_email in recent_emails:
                if isinstance(recent_email, bytes):
                    recent_email = recent_email.decode('utf-8')
                
                # Calculate similarity ratio (0-1)
                similarity = Levenshtein.ratio(email.lower(), recent_email.lower())
                
                if similarity > max_similarity:
                    max_similarity = similarity
                
                # Flag if very similar but not identical
                if 0.99 > similarity >= self.similarity_threshold:
                    is_similar = True
                    logger.warning(f"Similar emails detected: '{email}' vs '{recent_email}' (similarity: {similarity:.2f})")
            
            return {
                "is_similar": is_similar,
                "max_similarity": max_similarity
            }
            
        except Exception as e:
            logger.error(f"Error in similarity check: {e}")
            return {"is_similar": False, "max_similarity": 0.0}
    
    async def _store_recent_email(self, email: str):
        """Store email in Redis list for pattern detection"""
        try:
            async with self.redis.pipeline(transaction=True) as pipe:
                # Add to list
                pipe.lpush(self.recent_emails_key, email)
                # Trim to keep only last 100
                pipe.ltrim(self.recent_emails_key, 0, 99)
                # Set expiry
                pipe.expire(self.recent_emails_key, self.recent_emails_ttl)
                await pipe.execute()
        except Exception as e:
            logger.error(f"Error storing recent email: {e}")
