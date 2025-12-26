"""
Email Deliverability Service - SMTP Mailbox Verification
"""
import asyncio
import smtplib
import dns.resolver
from typing import Optional
from app.core.logging import get_logger

logger = get_logger(__name__)

class EmailDeliverabilityService:
    """Service to verify email deliverability using SMTP"""
    
    def __init__(self):
        self.timeout = 10  # SMTP timeout in seconds
        self.from_email = "verify@example.com"  # Sender address for SMTP verification
        
    async def verify_email_deliverability(self, email: str) -> dict:
        """
        Verify if an email address actually exists using SMTP
        
        Returns:
            dict with keys:
                - is_deliverable: bool
                - smtp_valid: bool
                - catch_all: bool (True if domain accepts all emails)
                - error: str or None
        """
        result = {
            "is_deliverable": False,
            "smtp_valid": False,
            "catch_all": False,
            "error": None
        }
        
        try:
            local_part, domain = email.split('@')
        except ValueError:
            result["error"] = "Invalid email format"
            return result
        
        # Get MX records
        mx_records = await self._get_mx_records(domain)
        if not mx_records:
            result["error"] = "No MX records found"
            return result
        
        # Try SMTP verification with the primary MX server
        mx_host = mx_records[0]
        smtp_result = await self._verify_smtp(mx_host, email)
        
        result.update(smtp_result)
        
        return result
    
    async def _get_mx_records(self, domain: str) -> list:
        """Get MX records for a domain"""
        loop = asyncio.get_event_loop()
        
        try:
            def resolve_mx():
                answers = dns.resolver.resolve(domain, 'MX')
                # Sort by priority (lower number = higher priority)
                return [str(rdata.exchange).rstrip('.') for rdata in sorted(answers, key=lambda x: x.preference)]
            
            mx_records = await loop.run_in_executor(None, resolve_mx)
            return mx_records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return []
        except Exception as e:
            logger.warning(f"MX lookup failed for {domain}: {e}")
            return []
    
    async def _verify_smtp(self, mx_host: str, email: str) -> dict:
        """
        Verify email using SMTP protocol
        
        IMPORTANT: This is a grey-area technique. Some servers may:
        - Block verification attempts
        - Always return positive results (catch-all)
        - Rate limit connections
        
        Use with caution in production!
        """
        result = {
            "is_deliverable": False,
            "smtp_valid": False,
            "catch_all": False,
            "error": None
        }
        
        loop = asyncio.get_event_loop()
        
        try:
            def smtp_verify():
                # Connect to SMTP server
                server = smtplib.SMTP(timeout=self.timeout)
                server.set_debuglevel(0)  # Disable debug output
                
                try:
                    server.connect(mx_host, 25)
                    server.helo(server.local_hostname)
                    server.mail(self.from_email)
                    
                    # RCPT TO command - checks if recipient exists
                    code, message = server.rcpt(email)
                    
                    # Also check a random email to detect catch-all
                    random_email = f"random{asyncio.get_event_loop().time()}@{email.split('@')[1]}"
                    code_random, _ = server.rcpt(random_email)
                    
                    server.quit()
                    
                    return {
                        "code": code,
                        "message": message.decode() if isinstance(message, bytes) else str(message),
                        "random_code": code_random
                    }
                except smtplib.SMTPServerDisconnected:
                    return {"error": "Server disconnected"}
                except smtplib.SMTPRecipientsRefused:
                    return {"code": 550, "message": "Recipient refused"}
                except Exception as e:
                    return {"error": str(e)}
                finally:
                    try:
                        server.quit()
                    except:
                        pass
            
            smtp_response = await loop.run_in_executor(None, smtp_verify)
            
            if "error" in smtp_response and smtp_response.get("error"):
                result["error"] = smtp_response["error"]
                logger.info(f"SMTP verification error for {email}: {smtp_response['error']}")
                return result
            
            code = smtp_response.get("code", 0)
            random_code = smtp_response.get("random_code", 0)
            
            # 250 = OK, 251 = User not local (will forward)
            if code in [250, 251]:
                result["smtp_valid"] = True
                result["is_deliverable"] = True
                
                # Check if it's a catch-all domain
                if random_code in [250, 251]:
                    result["catch_all"] = True
                    logger.warning(f"Catch-all domain detected: {email.split('@')[1]}")
            else:
                result["error"] = f"SMTP code {code}: {smtp_response.get('message', 'Unknown')}"
                logger.info(f"Email {email} failed SMTP verification: {result['error']}")
        
        except asyncio.TimeoutError:
            result["error"] = "SMTP connection timeout"
            logger.warning(f"SMTP timeout for {mx_host}")
        except Exception as e:
            result["error"] = f"SMTP verification failed: {str(e)}"
            logger.error(f"SMTP error for {email}: {e}")
        
        return result
