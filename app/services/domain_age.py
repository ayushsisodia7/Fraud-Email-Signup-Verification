"""
Domain Age Verification Service
"""
import asyncio
import functools
import json
from datetime import datetime
import whois
from app.core.logging import get_logger
from app.core.config import settings
from app.core.metrics import CACHE_EVENTS_TOTAL, SIGNAL_LATENCY_SECONDS

logger = get_logger(__name__)

class DomainAgeService:
    """Service to check domain registration age using WHOIS"""
    
    def __init__(
        self,
        redis_client=None,
        suspicious_age_days: int = settings.NEW_DOMAIN_AGE_DAYS,
        cache_ttl_seconds: int = settings.WHOIS_CACHE_TTL_SECONDS,
        negative_cache_ttl_seconds: int = settings.WHOIS_NEGATIVE_CACHE_TTL_SECONDS,
    ):
        self.suspicious_age_days = suspicious_age_days
        self.redis = redis_client
        self.cache_ttl_seconds = cache_ttl_seconds
        self.negative_cache_ttl_seconds = negative_cache_ttl_seconds

    def _cache_key(self, domain: str) -> str:
        return f"cache:domain_age:{domain.lower()}"

    def _build_result(self, domain: str, creation_date) -> dict:
        result = {
            "creation_date": None,
            "age_days": None,
            "is_new_domain": False,
            "is_suspicious": False
        }

        if not creation_date:
            return result

        if isinstance(creation_date, list):
            creation_date = min(creation_date)

        if not creation_date:
            return result

        result["creation_date"] = creation_date

        now = datetime.now()
        if creation_date.tzinfo is not None:
            from datetime import timezone
            now = datetime.now(timezone.utc)

        age = now - creation_date
        result["age_days"] = age.days

        if age.days < self.suspicious_age_days:
            result["is_new_domain"] = True
            result["is_suspicious"] = True
            logger.info(f"New domain detected: {domain} (age: {age.days} days)")
        else:
            logger.info(f"Domain {domain} is {age.days} days old")

        return result
        
    async def check_domain_age(self, domain: str) -> dict:
        """
        Check domain registration age via WHOIS lookup
        
        Returns:
            dict with keys:
                - creation_date: datetime or None
                - age_days: int or None
                - is_new_domain: bool (True if < 30 days old)
                - is_suspicious: bool
        """
        cache_key = self._cache_key(domain)
        if self.redis is not None:
            try:
                cached = await self.redis.get(cache_key)
                if cached:
                    CACHE_EVENTS_TOTAL.labels(cache="whois", event="hit").inc()
                    payload = json.loads(cached)
                    creation_date_raw = payload.get("creation_date")
                    creation_date = None
                    if creation_date_raw:
                        # Stored as ISO8601; datetime.fromisoformat supports offsets.
                        creation_date = datetime.fromisoformat(creation_date_raw)
                    return self._build_result(domain, creation_date)
                CACHE_EVENTS_TOTAL.labels(cache="whois", event="miss").inc()
            except Exception as e:
                logger.warning(f"Domain age cache read failed for {domain}: {e}")
                CACHE_EVENTS_TOTAL.labels(cache="whois", event="error").inc()
        
        try:
            # Run synchronous WHOIS in executor
            with SIGNAL_LATENCY_SECONDS.labels(signal="whois").time():
                loop = asyncio.get_event_loop()
                func = functools.partial(whois.whois, domain)
                w = await loop.run_in_executor(None, func)
            
            # WHOIS can return creation_date as datetime, list of datetimes, or None
            creation_date = getattr(w, "creation_date", None)
            result = self._build_result(domain, creation_date)

            if self.redis is not None:
                try:
                    payload = {
                        "creation_date": result["creation_date"].isoformat() if result["creation_date"] else None,
                    }
                    ttl = self.cache_ttl_seconds if result["creation_date"] else self.negative_cache_ttl_seconds
                    await self.redis.set(cache_key, json.dumps(payload), ex=ttl)
                except Exception as e:
                    logger.warning(f"Domain age cache write failed for {domain}: {e}")
                
        except whois.parser.PywhoisError as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            result = self._build_result(domain, None)
            if self.redis is not None:
                try:
                    await self.redis.set(cache_key, json.dumps({"creation_date": None}), ex=self.negative_cache_ttl_seconds)
                except Exception as ce:
                    logger.warning(f"Domain age negative-cache write failed for {domain}: {ce}")
        except Exception as e:
            logger.error(f"Error checking domain age for {domain}: {e}")
            result = self._build_result(domain, None)
            if self.redis is not None:
                try:
                    await self.redis.set(cache_key, json.dumps({"creation_date": None}), ex=self.negative_cache_ttl_seconds)
                except Exception as ce:
                    logger.warning(f"Domain age negative-cache write failed for {domain}: {ce}")
        
        return result
