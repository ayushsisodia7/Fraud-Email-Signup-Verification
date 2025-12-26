"""
Admin Dashboard API Endpoints for viewing fraud stats
"""
from fastapi import APIRouter, HTTPException
from typing import List, Optional
import redis.asyncio as redis
from datetime import datetime, timedelta
from app.core.config import settings
from app.core.logging import get_logger

router = APIRouter()
logger = get_logger(__name__)

# Initialize Redis
redis_client = None

async def get_redis():
    global redis_client
    if redis_client is None:
        redis_client = redis.from_url(
            f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}",
            encoding="utf-8",
            decode_responses=True
        )
    return redis_client


@router.get("/stats/overview")
async def get_fraud_overview():
    """Get overall fraud detection statistics"""
    try:
        r = await get_redis()
        
        # Get velocity data (simplified)
        ip_keys = []
        async for key in r.scan_iter("velocity:ip:*"):
            ip_keys.append(key)
        
        domain_keys = []
        async for key in r.scan_iter("velocity:domain:*"):
            domain_keys.append(key)
        
        # Get pattern data
        recent_emails = await r.llen("pattern:recent_emails")
        
        return {
            "total_unique_ips": len(ip_keys),
            "total_unique_domains": len(domain_keys),
            "recent_signups_tracked": recent_emails,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch statistics")


@router.get("/stats/recent-ips")
async def get_recent_ips(limit: int = 20):
    """Get most active IPs"""
    try:
        r = await get_redis()
        
        ip_data = []
        async for key in r.scan_iter("velocity:ip:*", count=limit):
            ip = key.replace("velocity:ip:", "")
            count = await r.get(key)
            ttl = await r.ttl(key)
            
            ip_data.append({
                "ip": ip,
                "count": int(count) if count else 0,
                "ttl_seconds": ttl
            })
        
        # Sort by count descending
        ip_data.sort(key=lambda x: x["count"], reverse=True)
        
        return {
            "ip_activity": ip_data[:limit],
            "total_tracked": len(ip_data)
        }
    except Exception as e:
        logger.error(f"Error fetching IP stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch IP statistics")


@router.get("/stats/recent-emails")
async def get_recent_emails():
    """Get recently analyzed emails (for pattern detection)"""
    try:
        r = await get_redis()
        
        # Get last 50 emails from pattern detection
        emails = await r.lrange("pattern:recent_emails", 0, 49)
        
        return {
            "recent_emails": emails,
            "count": len(emails)
        }
    except Exception as e:
        logger.error(f"Error fetching recent emails: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch recent emails")


@router.post("/admin/clear-velocity/{ip_address}")
async def clear_ip_velocity(ip_address: str):
    """Clear velocity counter for a specific IP (admin action)"""
    try:
        r = await get_redis()
        key = f"velocity:ip:{ip_address}"
        deleted = await r.delete(key)
        
        return {
            "success": deleted > 0,
            "message": f"Cleared velocity for {ip_address}" if deleted else f"No data found for {ip_address}"
        }
    except Exception as e:
        logger.error(f"Error clearing velocity: {e}")
        raise HTTPException(status_code=500, detail="Failed to clear velocity data")


@router.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        r = await get_redis()
        await r.ping()
        
        return {
            "status": "healthy",
            "redis": "connected",
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "redis": "disconnected",
            "error": str(e)
        }
