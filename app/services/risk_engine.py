import asyncio
import functools
import math
import dns.resolver
import redis.asyncio as redis
from app.core.config import settings
from app.core.metrics import SIGNAL_LATENCY_SECONDS, DECISIONS_TOTAL
from app.services.validators import validate_email_syntax
from app.services.domain_manager import DomainManager
from app.services.ip_intelligence import IPIntelligenceService
from app.services.domain_age import DomainAgeService
from app.services.pattern_detection import PatternDetectionService
from app.services.email_deliverability import EmailDeliverabilityService
from app.services.webhook import WebhookService
from app.core.logging import get_logger

logger = get_logger(__name__)

class RiskEngine:
    def __init__(self):
        # We'll initialize Redis connection here, managing it as a shared resource would be better
        # but for simplicity we keep it here. Ideally it should be injected.
        self.redis = redis.from_url(f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}", encoding="utf-8", decode_responses=True)
        self.domain_manager = DomainManager(self.redis)
        self.ip_intelligence = IPIntelligenceService(
            redis_client=self.redis,
            cache_ttl_seconds=settings.IP_INTEL_CACHE_TTL_SECONDS,
            negative_cache_ttl_seconds=settings.IP_INTEL_NEGATIVE_CACHE_TTL_SECONDS,
        )
        self.domain_age_service = DomainAgeService(
            redis_client=self.redis,
            suspicious_age_days=settings.NEW_DOMAIN_AGE_DAYS,
            cache_ttl_seconds=settings.WHOIS_CACHE_TTL_SECONDS,
            negative_cache_ttl_seconds=settings.WHOIS_NEGATIVE_CACHE_TTL_SECONDS,
        )
        self.pattern_detection = PatternDetectionService(self.redis)
        self.email_deliverability = EmailDeliverabilityService()
        self.webhook_service = WebhookService()
        self.major_providers = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com"}

    def _add_reason(self, reasons: list[dict], code: str, points: int, message: str, meta: dict | None = None) -> None:
        r = {"code": code, "points": int(points), "message": message}
        if meta:
            r["meta"] = meta
        reasons.append(r)

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
            with SIGNAL_LATENCY_SECONDS.labels(signal="mx_lookup").time():
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
            
            if ip_count > settings.VELOCITY_IP_LIMIT_PER_HOUR:
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
        reasons: list[dict] = []
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
            score += settings.SCORE_DISPOSABLE_DOMAIN
            signals["is_disposable"] = True
            self._add_reason(
                reasons,
                code="DISPOSABLE_DOMAIN",
                points=settings.SCORE_DISPOSABLE_DOMAIN,
                message=f"Domain {domain} is a known disposable email provider",
                meta={"domain": domain},
            )

        # Layer 3: MX Record
        mx_exists = await self.check_mx_record(domain)
        if not mx_exists:
            score += settings.SCORE_NO_MX
            signals["mx_found"] = False
            self._add_reason(
                reasons,
                code="NO_MX_RECORD",
                points=settings.SCORE_NO_MX,
                message=f"Domain {domain} has no MX records",
                meta={"domain": domain},
            )
        else:
            signals["mx_found"] = True

        # Layer 4: Local-Part Entropy
        entropy = self.calculate_entropy(local_part)
        signals["entropy_score"] = round(entropy, 2)
        if entropy > settings.ENTROPY_THRESHOLD:
            score += settings.SCORE_HIGH_ENTROPY
            self._add_reason(
                reasons,
                code="HIGH_ENTROPY_LOCAL_PART",
                points=settings.SCORE_HIGH_ENTROPY,
                message="Email local-part looks randomly generated (high entropy)",
                meta={"entropy": round(entropy, 2), "threshold": settings.ENTROPY_THRESHOLD},
            )

        # Layer 5: Velocity Check
        velocity_breach = await self.check_velocity(ip_address, domain)
        if velocity_breach:
            score += settings.SCORE_VELOCITY_BREACH
            signals["velocity_breach"] = True
            self._add_reason(
                reasons,
                code="VELOCITY_BREACH",
                points=settings.SCORE_VELOCITY_BREACH,
                message="High signup velocity detected from this IP",
                meta={"ip_address": ip_address, "limit_per_hour": settings.VELOCITY_IP_LIMIT_PER_HOUR},
            )

        # NEW Layer 6: VPN/Proxy Detection
        ip_info = await self.ip_intelligence.analyze_ip(ip_address)
        signals["is_vpn"] = ip_info["is_vpn"]
        signals["is_proxy"] = ip_info["is_proxy"]
        signals["is_datacenter"] = ip_info["is_datacenter"]
        signals["ip_country"] = ip_info["country"]
        
        if ip_info["is_vpn"] or ip_info["is_proxy"]:
            score += settings.SCORE_VPN_OR_PROXY
            logger.warning(f"VPN/Proxy detected for IP {ip_address}")
            self._add_reason(
                reasons,
                code="VPN_OR_PROXY",
                points=settings.SCORE_VPN_OR_PROXY,
                message="Signup originated from a VPN/proxy",
                meta={"ip_address": ip_address, "country": ip_info.get("country")},
            )
        elif ip_info["is_datacenter"]:
            score += settings.SCORE_DATACENTER_IP
            logger.info(f"Datacenter IP detected: {ip_address}")
            self._add_reason(
                reasons,
                code="DATACENTER_IP",
                points=settings.SCORE_DATACENTER_IP,
                message="Signup originated from a datacenter/cloud IP",
                meta={"ip_address": ip_address, "country": ip_info.get("country")},
            )

        # NEW Layer 7: Domain Age Check
        domain_age_info = await self.domain_age_service.check_domain_age(domain)
        signals["domain_age_days"] = domain_age_info["age_days"]
        signals["is_new_domain"] = domain_age_info["is_new_domain"]
        
        if domain_age_info["is_new_domain"]:
            score += settings.SCORE_NEW_DOMAIN
            logger.warning(f"New domain detected: {domain} (age: {domain_age_info['age_days']} days)")
            self._add_reason(
                reasons,
                code="NEW_DOMAIN",
                points=settings.SCORE_NEW_DOMAIN,
                message="Email domain is newly registered",
                meta={"domain": domain, "age_days": domain_age_info.get("age_days"), "threshold_days": settings.NEW_DOMAIN_AGE_DAYS},
            )

        # NEW Layer 8: Pattern Detection
        pattern_info = await self.pattern_detection.analyze_patterns(email, normalized_email)
        signals["pattern_detected"] = pattern_info["pattern_type"]
        signals["is_sequential"] = pattern_info["is_sequential"]
        signals["has_number_suffix"] = pattern_info["has_number_suffix"]
        signals["is_similar_to_recent"] = pattern_info["is_similar_to_recent"]
        
        if pattern_info["is_sequential"]:
            score += settings.SCORE_PATTERN_SEQUENTIAL
            self._add_reason(
                reasons,
                code="SEQUENTIAL_PATTERN",
                points=settings.SCORE_PATTERN_SEQUENTIAL,
                message="Email local-part looks sequential (bot-like)",
            )
        elif pattern_info["has_number_suffix"]:
            score += settings.SCORE_PATTERN_NUMBER_SUFFIX
            self._add_reason(
                reasons,
                code="NUMBER_SUFFIX_PATTERN",
                points=settings.SCORE_PATTERN_NUMBER_SUFFIX,
                message="Email local-part ends with a multi-digit number suffix",
            )
        
        if pattern_info["is_similar_to_recent"]:
            score += settings.SCORE_PATTERN_SIMILAR_TO_RECENT
            logger.warning(f"Similar email pattern detected: {email}")
            self._add_reason(
                reasons,
                code="SIMILAR_TO_RECENT",
                points=settings.SCORE_PATTERN_SIMILAR_TO_RECENT,
                message="Email is very similar to a recently submitted email",
            )

        # NEW Layer 9: SMTP Email Deliverability Check (Optional)
        if settings.ENABLE_SMTP_VERIFICATION:
            deliverability_info = await self.email_deliverability.verify_email_deliverability(email)
            signals["smtp_deliverable"] = deliverability_info["is_deliverable"]
            signals["smtp_valid"] = deliverability_info["smtp_valid"]
            signals["catch_all_domain"] = deliverability_info["catch_all"]
            
            if not deliverability_info["is_deliverable"] and not deliverability_info["catch_all"]:
                # Email doesn't exist and it's not a catch-all domain
                score += settings.SCORE_SMTP_UNDELIVERABLE
                logger.warning(f"Email not deliverable: {email}")
                self._add_reason(
                    reasons,
                    code="SMTP_UNDELIVERABLE",
                    points=settings.SCORE_SMTP_UNDELIVERABLE,
                    message="SMTP verification indicates the mailbox does not exist",
                )
            elif deliverability_info["catch_all"]:
                # Catch-all domains are suspicious (accept any email)
                score += settings.SCORE_SMTP_CATCH_ALL
                logger.info(f"Catch-all domain detected: {domain}")
                self._add_reason(
                    reasons,
                    code="SMTP_CATCH_ALL",
                    points=settings.SCORE_SMTP_CATCH_ALL,
                    message="Domain appears to be catch-all (accepts any mailbox)",
                )
        else:
            # SMTP verification disabled
            signals["smtp_deliverable"] = None
            signals["smtp_valid"] = None
            signals["catch_all_domain"] = None

        # Final Result
        level = "LOW"
        action = "ALLOW"
        
        # Adjust logic: If sum exceeds 100 easily, we should ensure the levels make sense.
        # User defined:
        # 0-30: LOW (Allow)
        # 31-70: MEDIUM (Challenge/Captcha)
        # 71-100: HIGH (Block)
        
        total_score = min(score, 100)
        
        if settings.RISK_LOW_MAX < total_score <= settings.RISK_MEDIUM_MAX:
            level = "MEDIUM"
            action = "CHALLENGE"
        elif total_score > settings.RISK_MEDIUM_MAX:
            level = "HIGH"
            action = "BLOCK"

        result = {
            "email": email,
            "normalized_email": normalized_email,
            "reasons": reasons,
            "risk_summary": {
                "score": total_score,
                "level": level,
                "action": action
            },
            "signals": signals
        }

        DECISIONS_TOTAL.labels(level=level, action=action).inc()
        
        logger.info(f"Analysis result for {email}: {result['risk_summary']}")
        
        # Send webhook notification for high-risk signups
        if level in ["MEDIUM", "HIGH"]:
            await self.webhook_service.notify_high_risk_signup(
                email=email,
                normalized_email=normalized_email,
                risk_summary=result["risk_summary"],
                signals=signals,
                reasons=reasons,
                ip_address=ip_address,
                user_agent=user_agent
            )
        
        return result

    async def analyze_fast(self, email: str, ip_address: str, user_agent: str):
        """
        Fast analysis: avoids slow/external checks (IP intel, WHOIS, SMTP) and avoids side-effect checks
        (velocity counters, pattern storage). Intended for high-throughput / low-latency flows when
        background enrichment is enabled.
        """
        logger.info(f"Fast-analyzing signup attempt: {email} from {ip_address}")

        score = 0
        reasons: list[dict] = []
        signals = {
            "is_disposable": False,
            "mx_found": True,
            "velocity_breach": None,
            "entropy_score": 0.0,
            "is_alias": False,
            "is_vpn": None,
            "is_proxy": None,
            "is_datacenter": None,
            "ip_country": None,
            "domain_age_days": None,
            "is_new_domain": None,
            "pattern_detected": None,
            "is_sequential": None,
            "has_number_suffix": None,
            "is_similar_to_recent": None,
            "smtp_deliverable": None,
            "smtp_valid": None,
            "catch_all_domain": None,
        }

        if not validate_email_syntax(email):
            raise ValueError("Invalid email format")

        try:
            local_part, domain = email.split("@")
        except ValueError:
            raise ValueError("Invalid email format")

        normalized_local = local_part
        if "+" in local_part:
            signals["is_alias"] = True
            normalized_local = local_part.split("+")[0]
        normalized_email = f"{normalized_local}@{domain}"

        is_disposable = await self.domain_manager.is_disposable(domain)
        if is_disposable:
            score += settings.SCORE_DISPOSABLE_DOMAIN
            signals["is_disposable"] = True
            self._add_reason(
                reasons,
                code="DISPOSABLE_DOMAIN",
                points=settings.SCORE_DISPOSABLE_DOMAIN,
                message=f"Domain {domain} is a known disposable email provider",
                meta={"domain": domain},
            )

        mx_exists = await self.check_mx_record(domain)
        if not mx_exists:
            score += settings.SCORE_NO_MX
            signals["mx_found"] = False
            self._add_reason(
                reasons,
                code="NO_MX_RECORD",
                points=settings.SCORE_NO_MX,
                message=f"Domain {domain} has no MX records",
                meta={"domain": domain},
            )

        entropy = self.calculate_entropy(local_part)
        signals["entropy_score"] = round(entropy, 2)
        if entropy > settings.ENTROPY_THRESHOLD:
            score += settings.SCORE_HIGH_ENTROPY
            self._add_reason(
                reasons,
                code="HIGH_ENTROPY_LOCAL_PART",
                points=settings.SCORE_HIGH_ENTROPY,
                message="Email local-part looks randomly generated (high entropy)",
                meta={"entropy": round(entropy, 2), "threshold": settings.ENTROPY_THRESHOLD},
            )

        total_score = min(score, 100)
        level = "LOW"
        action = "ALLOW"
        if settings.RISK_LOW_MAX < total_score <= settings.RISK_MEDIUM_MAX:
            level = "MEDIUM"
            action = "CHALLENGE"
        elif total_score > settings.RISK_MEDIUM_MAX:
            level = "HIGH"
            action = "BLOCK"

        result = {
            "email": email,
            "normalized_email": normalized_email,
            "reasons": reasons,
            "risk_summary": {"score": total_score, "level": level, "action": action},
            "signals": signals,
        }

        DECISIONS_TOTAL.labels(level=level, action=action).inc()
        return result

    async def close(self):
        await self.redis.close()

