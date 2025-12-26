"""
IP Intelligence Service for VPN/Proxy Detection
"""
import httpx
from app.core.logging import get_logger

logger = get_logger(__name__)

class IPIntelligenceService:
    """Service to detect VPN, Proxy, and suspicious IP addresses"""
    
    def __init__(self):
        # Using ipapi.co for free IP intelligence
        # Alternative: ip-api.com, ipqualityscore.com (requires API key for better accuracy)
        self.api_url = "https://ipapi.co/{ip}/json/"
        self.timeout = 3.0  # Timeout in seconds
        
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
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(self.api_url.format(ip=ip_address))
                
                if response.status_code == 200:
                    data = response.json()
                    
                    result["country"] = data.get("country_name")
                    result["asn"] = data.get("asn")
                    result["org"] = data.get("org")
                    
                    # Detect VPN/Proxy/Datacenter based on organization name
                    # This is a heuristic approach - for production, use paid services
                    org_lower = (data.get("org") or "").lower()
                    
                    vpn_keywords = ["vpn", "proxy", "hosting", "cloud", "datacenter", 
                                   "amazon", "google cloud", "microsoft azure", "digitalocean",
                                   "ovh", "linode", "vultr", "hetzner"]
                    
                    for keyword in vpn_keywords:
                        if keyword in org_lower:
                            # Datacenter IPs are suspicious for signups
                            result["is_datacenter"] = True
                            
                            # More specific VPN/Proxy detection
                            if any(k in org_lower for k in ["vpn", "proxy"]):
                                result["is_vpn"] = True
                                result["is_proxy"] = True
                            break
                    
                    logger.info(f"IP analysis for {ip_address}: {result}")
                else:
                    logger.warning(f"IP API returned status {response.status_code} for {ip_address}")
                    
        except httpx.TimeoutException:
            logger.warning(f"Timeout querying IP intelligence for {ip_address}")
        except Exception as e:
            logger.error(f"Error analyzing IP {ip_address}: {e}")
        
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
