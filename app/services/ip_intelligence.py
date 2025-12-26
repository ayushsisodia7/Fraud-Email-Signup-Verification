"""
IP Intelligence Service for VPN/Proxy Detection
"""
import json
import httpx
from app.core.logging import get_logger
from app.core.config import settings
from app.core.metrics import CACHE_EVENTS_TOTAL, SIGNAL_LATENCY_SECONDS

logger = get_logger(__name__)

class IPIntelligenceService:
    """Service to detect VPN, Proxy, and suspicious IP addresses"""
    
    def __init__(
        self,
        redis_client=None,
        cache_ttl_seconds: int = settings.IP_INTEL_CACHE_TTL_SECONDS,
        negative_cache_ttl_seconds: int = settings.IP_INTEL_NEGATIVE_CACHE_TTL_SECONDS,
    ):
        # Using ipapi.co for free IP intelligence
        # Alternative: ip-api.com, ipqualityscore.com (requires API key for better accuracy)
        self.api_url = "https://ipapi.co/{ip}/json/"
        self.fallback_ipwhois_url = "https://ipwho.is/{ip}"
        self.fallback_ipapi_http_url = "http://ip-api.com/json/{ip}"
        self.timeout = 3.0  # Timeout in seconds
        self.redis = redis_client
        self.cache_ttl_seconds = cache_ttl_seconds
        self.negative_cache_ttl_seconds = negative_cache_ttl_seconds
        self.verify_ssl = settings.IP_INTEL_VERIFY_SSL

        self.fallback_providers = [
            p.strip().lower()
            for p in (settings.IP_INTEL_FALLBACK_PROVIDERS or "").split(",")
            if p.strip()
        ]

    def _cache_key(self, ip_address: str) -> str:
        return f"cache:ip_intel:{ip_address}"

    def _apply_org_heuristics(self, result: dict, org_value: str | None) -> None:
        org_lower = (org_value or "").lower()
        vpn_keywords = [
            "vpn", "proxy", "hosting", "cloud", "datacenter",
            "amazon", "google cloud", "microsoft azure", "digitalocean",
            "ovh", "linode", "vultr", "hetzner"
        ]
        for keyword in vpn_keywords:
            if keyword in org_lower:
                result["is_datacenter"] = True
                if any(k in org_lower for k in ["vpn", "proxy"]):
                    result["is_vpn"] = True
                    result["is_proxy"] = True
                break

    def _parse_ipapi(self, data: dict) -> dict:
        result = {
            "is_vpn": False,
            "is_proxy": False,
            "is_datacenter": False,
            "country": None,
            "asn": None,
            "org": None
        }

        result["country"] = (
            data.get("country_name")
            or data.get("country")
            or data.get("country_code")
            or data.get("country_code_iso3")
        )
        result["asn"] = data.get("asn")
        result["org"] = data.get("org")
        self._apply_org_heuristics(result, result["org"])
        return result

    def _parse_ipwhois(self, data: dict) -> dict:
        result = {
            "is_vpn": False,
            "is_proxy": False,
            "is_datacenter": False,
            "country": None,
            "asn": None,
            "org": None
        }
        # ipwho.is returns country fields directly
        result["country"] = data.get("country") or data.get("country_code")
        conn = data.get("connection") or {}
        result["asn"] = conn.get("asn")
        result["org"] = conn.get("org")
        self._apply_org_heuristics(result, result["org"])
        return result

    def _parse_ipapi_http(self, data: dict) -> dict:
        result = {
            "is_vpn": False,
            "is_proxy": False,
            "is_datacenter": False,
            "country": None,
            "asn": None,
            "org": None
        }
        # ip-api.com fields
        result["country"] = data.get("country") or data.get("countryCode")
        result["org"] = data.get("org")
        # "as" contains "ASxxx Org"
        result["asn"] = data.get("as")
        self._apply_org_heuristics(result, result["org"])
        return result

    async def _fetch_json(self, url: str, metric_signal: str) -> dict:
        with SIGNAL_LATENCY_SECONDS.labels(signal=metric_signal).time():
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl) as client:
                resp = await client.get(url)
        if resp.status_code != 200:
            raise RuntimeError(f"status={resp.status_code}")
        return resp.json()
        
    async def analyze_ip(self, ip_address: str) -> dict:
        """
        Analyze IP address for VPN, proxy, and geolocation information
        
        Returns:
            dict with keys:
                - is_vpn: bool
                - is_proxy: bool
                - is_datacenter: bool
                - country: str
                - asn: str (Autonomous System Number)
                - org: str (Organization)
        """
        result = {
            "is_vpn": False,
            "is_proxy": False,
            "is_datacenter": False,
            "country": None,
            "asn": None,
            "org": None
        }
        
        # Skip localhost and private IPs
        if self._is_private_ip(ip_address):
            logger.info(f"Skipping IP analysis for private/local IP: {ip_address}")
            return result

        cache_key = self._cache_key(ip_address)
        if self.redis is not None:
            try:
                cached = await self.redis.get(cache_key)
                if cached:
                    CACHE_EVENTS_TOTAL.labels(cache="ip_intel", event="hit").inc()
                    return json.loads(cached)
                CACHE_EVENTS_TOTAL.labels(cache="ip_intel", event="miss").inc()
            except Exception as e:
                logger.warning(f"IP intelligence cache read failed for {ip_address}: {e}")
                CACHE_EVENTS_TOTAL.labels(cache="ip_intel", event="error").inc()
        
        try:
            # Primary provider: ipapi.co
            data = await self._fetch_json(self.api_url.format(ip=ip_address), metric_signal="ip_intel_ipapi")
            if data.get("error"):
                # ipapi can return a 200 with an error payload (e.g. rate-limit).
                raise RuntimeError(f"ipapi error payload: {data}")
            result = self._parse_ipapi(data)
            logger.info(f"IP analysis (ipapi) for {ip_address}: {result}")
            if self.redis is not None:
                try:
                    await self.redis.set(cache_key, json.dumps(result), ex=self.cache_ttl_seconds)
                except Exception as e:
                    logger.warning(f"IP intelligence cache write failed for {ip_address}: {e}")
            return result

        except Exception as e:
            logger.warning(f"Primary IP provider failed for {ip_address}: {e}")

            # Fall back providers
            for provider in self.fallback_providers:
                try:
                    if provider == "ipwhois":
                        data = await self._fetch_json(
                            self.fallback_ipwhois_url.format(ip=ip_address),
                            metric_signal="ip_intel_ipwhois",
                        )
                        if data.get("success") is False:
                            raise RuntimeError(f"ipwhois error payload: {data}")
                        result = self._parse_ipwhois(data)
                    elif provider == "ipapi_http":
                        data = await self._fetch_json(
                            self.fallback_ipapi_http_url.format(ip=ip_address),
                            metric_signal="ip_intel_ipapi_http",
                        )
                        if data.get("status") and data.get("status") != "success":
                            raise RuntimeError(f"ip-api error payload: {data}")
                        result = self._parse_ipapi_http(data)
                    else:
                        continue

                    logger.info(f"IP analysis ({provider}) for {ip_address}: {result}")
                    if self.redis is not None:
                        try:
                            await self.redis.set(cache_key, json.dumps(result), ex=self.cache_ttl_seconds)
                        except Exception as ce:
                            logger.warning(f"IP intelligence cache write failed for {ip_address}: {ce}")
                    return result
                except Exception as fe:
                    logger.warning(f"Fallback provider {provider} failed for {ip_address}: {fe}")

            # If all providers fail: negative cache and return default result (fail open).
            if self.redis is not None:
                try:
                    await self.redis.set(cache_key, json.dumps(result), ex=self.negative_cache_ttl_seconds)
                except Exception as ne:
                    logger.warning(f"IP intelligence negative-cache write failed for {ip_address}: {ne}")
                    
            return result
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
            return True
        if ip.startswith("172."):
            parts = ip.split(".")
            if len(parts) >= 2:
                second_octet = int(parts[1])
                if 16 <= second_octet <= 31:
                    return True
        if ip == "localhost" or ip == "::1":
            return True
        return False
