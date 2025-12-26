"""
Webhook Notifications Service
Sends alerts for high-risk signups
"""
import httpx
import json
from typing import Optional, List
from app.core.logging import get_logger
from app.core.config import settings

logger = get_logger(__name__)

class WebhookService:
    """Service to send webhook notifications for fraud events"""
    
    def __init__(self):
        # Webhook URLs can be configured via environment variables
        self.webhook_urls = self._load_webhook_urls()
        self.timeout = 5.0  # Webhook timeout in seconds
        
    def _load_webhook_urls(self) -> List[str]:
        """Load webhook URLs from settings"""
        # Check if WEBHOOK_URLS is configured
        webhook_urls_str = getattr(settings, 'WEBHOOK_URLS', '')
        
        if not webhook_urls_str:
            logger.info("No webhook URLs configured")
            return []
        
        # Support comma-separated URLs
        urls = [url.strip() for url in webhook_urls_str.split(',') if url.strip()]
        logger.info(f"Loaded {len(urls)} webhook URL(s)")
        return urls
    
    async def notify_high_risk_signup(
        self,
        email: str,
        normalized_email: str,
        risk_summary: dict,
        signals: dict,
        ip_address: str,
        user_agent: str,
        reasons: list[dict] | None = None,
    ) -> bool:
        """
        Send webhook notification for high-risk signup attempts
        
        Args:
            email: The original email
            normalized_email: The normalized version
            risk_summary: Risk score, level, and action
            signals: All fraud signals
            ip_address: User's IP
            user_agent: User's browser
            
        Returns:
            bool: True if at least one webhook succeeded
        """
        if not self.webhook_urls:
            logger.debug("No webhooks configured, skipping notification")
            return False
        
        # Only send for MEDIUM and HIGH risk
        if risk_summary["level"] not in ["MEDIUM", "HIGH"]:
            return False
        
        payload = {
            "event": "high_risk_signup",
            "timestamp": self._get_timestamp(),
            "data": {
                "email": email,
                "normalized_email": normalized_email,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "risk_summary": risk_summary,
                "signals": signals,
                "reasons": reasons or []
            }
        }
        
        success_count = 0
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for webhook_url in self.webhook_urls:
                try:
                    response = await client.post(
                        webhook_url,
                        json=payload,
                        headers={"Content-Type": "application/json"}
                    )
                    
                    if response.status_code in [200, 201, 202, 204]:
                        success_count += 1
                        logger.info(f"Webhook sent successfully to {webhook_url} for {email}")
                    else:
                        logger.warning(
                            f"Webhook to {webhook_url} returned status {response.status_code}"
                        )
                        
                except httpx.TimeoutException:
                    logger.error(f"Webhook timeout for {webhook_url}")
                except Exception as e:
                    logger.error(f"Webhook error for {webhook_url}: {e}")
        
        return success_count > 0
    
    async def notify_blocked_signup(
        self,
        email: str,
        reason: str,
        ip_address: str
    ) -> bool:
        """Send notification when a signup is blocked"""
        if not self.webhook_urls:
            return False
        
        payload = {
            "event": "blocked_signup",
            "timestamp": self._get_timestamp(),
            "data": {
                "email": email,
                "ip_address": ip_address,
                "reason": reason
            }
        }
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for webhook_url in self.webhook_urls:
                try:
                    await client.post(webhook_url, json=payload)
                    logger.info(f"Block notification sent to {webhook_url}")
                except Exception as e:
                    logger.error(f"Webhook error: {e}")
        
        return True
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()
