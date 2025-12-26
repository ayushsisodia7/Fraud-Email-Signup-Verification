import httpx
import redis.asyncio as redis
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

REDIS_KEY_DISPOSABLE_DOMAINS = "disposable:domains"

class DomainManager:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    async def update_disposable_domains(self) -> int:
        """
        Fetches the latest disposable domains list and updates Redis.
        Returns the number of domains added.
        """
        logger.info(f"Fetching disposable domains from {settings.DISPOSABLE_EMAILS_URL}")
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(settings.DISPOSABLE_EMAILS_URL, timeout=10.0)
                response.raise_for_status()
            
            content = response.text
            domains = set()
            for line in content.splitlines():
                domain = line.strip().lower()
                if domain and not domain.startswith("#"):
                    domains.add(domain)
            
            if not domains:
                logger.warning("Fetched list is empty. Skipping update.")
                return 0

            # Use a pipeline to refresh the set
            async with self.redis.pipeline(transaction=True) as pipe:
                pipe.delete(REDIS_KEY_DISPOSABLE_DOMAINS)
                
                # Batch add to avoid hitting command size limits
                chunk_size = 5000
                domain_list = list(domains)
                for i in range(0, len(domain_list), chunk_size):
                    chunk = domain_list[i:i + chunk_size]
                    pipe.sadd(REDIS_KEY_DISPOSABLE_DOMAINS, *chunk)
                
                await pipe.execute()
            
            count = len(domains)
            logger.info(f"Successfully updated disposable domains list. Count: {count}")
            return count

        except httpx.RequestError as e:
            logger.error(f"Network error while fetching disposable domains: {e}")
            return 0
        except Exception as e:
            logger.error(f"Unexpected error updating disposable domains: {e}")
            return 0

    async def is_disposable(self, domain: str) -> bool:
        return await self.redis.sismember(REDIS_KEY_DISPOSABLE_DOMAINS, domain.lower())
