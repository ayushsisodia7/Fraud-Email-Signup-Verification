"""
Domain Age Verification Service
"""
import asyncio
import functools
from datetime import datetime
import whois
from app.core.logging import get_logger

logger = get_logger(__name__)

class DomainAgeService:
    """Service to check domain registration age using WHOIS"""
    
    def __init__(self):
        self.suspicious_age_days = 30  # Domains newer than 30 days are suspicious
        
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
        result = {
            "creation_date": None,
            "age_days": None,
            "is_new_domain": False,
            "is_suspicious": False
        }
        
        try:
            # Run synchronous WHOIS in executor
            loop = asyncio.get_event_loop()
            func = functools.partial(whois.whois, domain)
            w = await loop.run_in_executor(None, func)
            
            # WHOIS can return creation_date as datetime, list of datetimes, or None
            creation_date = w.creation_date
            
            if isinstance(creation_date, list):
                # Take the earliest date if multiple
                creation_date = min(creation_date)
            
            if creation_date:
                result["creation_date"] = creation_date
                
                # Calculate age
                now = datetime.now()
                if creation_date.tzinfo is not None:
                    # Make now timezone-aware to match
                    from datetime import timezone
                    now = datetime.now(timezone.utc)
                
                age = now - creation_date
                result["age_days"] = age.days
                
                # Flag new domains
                if age.days < self.suspicious_age_days:
                    result["is_new_domain"] = True
                    result["is_suspicious"] = True
                    logger.info(f"New domain detected: {domain} (age: {age.days} days)")
                else:
                    logger.info(f"Domain {domain} is {age.days} days old")
            else:
                logger.warning(f"Could not determine creation date for {domain}")
                
        except whois.parser.PywhoisError as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {e}")
        except Exception as e:
            logger.error(f"Error checking domain age for {domain}: {e}")
        
        return result
