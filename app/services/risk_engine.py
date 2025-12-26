import asyncio
import functools
import math
import dns.resolver
import redis.asyncio as redis
from app.core.config import settings
from app.services.validators import validate_email_syntax
from app.services.domain_manager import DomainManager
from app.services.ip_intelligence import IPIntelligenceService
from app.services.domain_age import DomainAgeService
from app.services.pattern_detection import PatternDetectionService
from app.core.logging import get_logger

logger = get_logger(__name__)

class RiskEngine:
    def __init__(self):
        # We'll initialize Redis connection here, managing it as a shared resource would be better
        # but for simplicity we keep it here. Ideally it should be injected.
        self.redis = redis.from_url(f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}", encoding="utf-8", decode_responses=True)
        self.domain_manager = DomainManager(self.redis)
        self.ip_intelligence = IPIntelligenceService()
        self.domain_age_service = DomainAgeService()
        self.pattern_detection = PatternDetectionService(self.redis)
        self.major_providers = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com"}

    def calculate_entropy(self, text: str) -> float:
        """Calculates Shannon Entropy of a string."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

    async def check_mx_record(self, domain: str) -> bool:
        """Checks if MX record exists for the domain."""
        loop = asyncio.get_event_loop()
        try:
            # Run synchronous DNS resolver in a separate thread
            func = functools.partial(dns.resolver.resolve, domain, 'MX')
            answers = await loop.run_in_executor(None, func)
            return True if answers else False
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return False
        except Exception as e:
            logger.warning(f"DNS lookup failed for {domain}: {e}")
            # Fail safe: if DNS fails, usually we don't block unless strict.
            # Returning False means 'No MX Found' -> High Risk.
            return False

    async def check_velocity(self, ip_address: str, domain: str) -> bool:
        """
        Increments checks for IP and Domain. Returns True if velocity is breached.
        """
        is_breach = False
        
        try:
            # IP Velocity
            ip_key = f"velocity:ip:{ip_address}"
            async with self.redis.pipeline(transaction=True) as pipe:
                pipe.incr(ip_key)
                pipe.expire(ip_key, 3600)
                results = await pipe.execute()
                ip_count = results[0]
            
            if ip_count > 10:
                is_breach = True

            # Domain Velocity (Skip major providers)
            if domain not in self.major_providers:
                domain_key = f"velocity:domain:{domain}"
                async with self.redis.pipeline(transaction=True) as pipe:
                    pipe.incr(domain_key)
                    pipe.expire(domain_key, 3600)
                    await pipe.execute()
        except Exception as e:
            logger.error(f"Redis error during velocity check: {e}")
            # Fail open for velocity checks if Redis is down
            return False

        return is_breach

    async def analyze(self, email: str, ip_address: str, user_agent: str):
        logger.info(f"Analyzing signup attempt: {email} from {ip_address}")
        
        score = 0
        signals = {
            "is_disposable": False,
            "mx_found": True,
            "velocity_breach": False,
            "entropy_score": 0.0,
            "is_alias": False,
            # New signals
            "is_vpn": False,
            "is_proxy": False,
            "is_datacenter": False,
            "ip_country": None,
            "domain_age_days": None,
            "is_new_domain": False,
            "pattern_detected": None,
            "is_sequential": False,
            "has_number_suffix": False,
            "is_similar_to_recent": False
        }

        # Layer 1: Syntax
        if not validate_email_syntax(email):
            logger.info(f"Invalid email syntax: {email}")
            raise ValueError("Invalid email format")

        try:
            local_part, domain = email.split('@')
        except ValueError:
             raise ValueError("Invalid email format")

        # Detect Alias
        normalized_local = local_part
        is_alias = False
        if "+" in local_part:
            is_alias = True
            normalized_local = local_part.split("+")[0]
        
        normalized_email = f"{normalized_local}@{domain}"
        signals["is_alias"] = is_alias

        # Layer 2: Domain Blacklist (Redis)
        is_disposable = await self.domain_manager.is_disposable(domain)
        if is_disposable:
            score += 90
            signals["is_disposable"] = True

        # Layer 3: MX Record
        mx_exists = await self.check_mx_record(domain)
        if not mx_exists:
            score += 100
            signals["mx_found"] = False
        else:
            signals["mx_found"] = True

        # Layer 4: Local-Part Entropy
        entropy = self.calculate_entropy(local_part)
        signals["entropy_score"] = round(entropy, 2)
        if entropy > 4.5:
            score += 30

        # Layer 5: Velocity Check
        velocity_breach = await self.check_velocity(ip_address, domain)
        if velocity_breach:
            score += 40
            signals["velocity_breach"] = True

        # NEW Layer 6: VPN/Proxy Detection
        ip_info = await self.ip_intelligence.analyze_ip(ip_address)
        signals["is_vpn"] = ip_info["is_vpn"]
        signals["is_proxy"] = ip_info["is_proxy"]
        signals["is_datacenter"] = ip_info["is_datacenter"]
        signals["ip_country"] = ip_info["country"]
        
        if ip_info["is_vpn"] or ip_info["is_proxy"]:
            score += 50
            logger.warning(f"VPN/Proxy detected for IP {ip_address}")
        elif ip_info["is_datacenter"]:
            score += 30
            logger.info(f"Datacenter IP detected: {ip_address}")

        # NEW Layer 7: Domain Age Check
        domain_age_info = await self.domain_age_service.check_domain_age(domain)
        signals["domain_age_days"] = domain_age_info["age_days"]
        signals["is_new_domain"] = domain_age_info["is_new_domain"]
        
        if domain_age_info["is_new_domain"]:
            score += 60
            logger.warning(f"New domain detected: {domain} (age: {domain_age_info['age_days']} days)")

        # NEW Layer 8: Pattern Detection
        pattern_info = await self.pattern_detection.analyze_patterns(email, normalized_email)
        signals["pattern_detected"] = pattern_info["pattern_type"]
        signals["is_sequential"] = pattern_info["is_sequential"]
        signals["has_number_suffix"] = pattern_info["has_number_suffix"]
        signals["is_similar_to_recent"] = pattern_info["is_similar_to_recent"]
        
        if pattern_info["is_sequential"]:
            score += 40
        elif pattern_info["has_number_suffix"]:
            score += 25
        
        if pattern_info["is_similar_to_recent"]:
            score += 35
            logger.warning(f"Similar email pattern detected: {email}")

        # Final Result
        level = "LOW"
        action = "ALLOW"
        
        # Adjust logic: If sum exceeds 100 easily, we should ensure the levels make sense.
        # User defined:
        # 0-30: LOW (Allow)
        # 31-70: MEDIUM (Challenge/Captcha)
        # 71-100: HIGH (Block)
        
        total_score = min(score, 100)
        
        if 31 <= total_score <= 70:
            level = "MEDIUM"
            action = "CHALLENGE"
        elif total_score >= 71:
            level = "HIGH"
            action = "BLOCK"

        result = {
            "email": email,
            "normalized_email": normalized_email,
            "risk_summary": {
                "score": total_score,
                "level": level,
                "action": action
            },
            "signals": signals
        }
        
        logger.info(f"Analysis result for {email}: {result['risk_summary']}")
        return result

    async def close(self):
        await self.redis.close()

