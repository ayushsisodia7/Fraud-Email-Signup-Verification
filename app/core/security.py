from fastapi import Header, HTTPException
from starlette.requests import Request
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


def require_admin_api_key(
    request: Request,
    x_admin_api_key: str | None = Header(default=None, alias="X-Admin-API-Key"),
) -> None:
    """
    Protect admin endpoints with an API key.

    - If ADMIN_API_KEY is empty, auth is disabled (dev-only convenience).
    - If ADMIN_API_KEY is set, clients must send header: X-Admin-API-Key: <key>
    """
    expected = (settings.ADMIN_API_KEY or "").strip()
    if not expected:
        # Fail-closed outside dev to prevent accidental public exposure.
        if (settings.ENVIRONMENT or "dev").lower() != "dev":
            raise HTTPException(status_code=503, detail="Admin API key not configured")
        logger.warning("ADMIN_API_KEY is not set; admin endpoints are unprotected (dev mode).")
        return

    client_host = getattr(request.client, "host", None)
    path = request.url.path

    if not x_admin_api_key or x_admin_api_key != expected:
        logger.warning(f"Admin auth failed for {path} from {client_host}")
        raise HTTPException(status_code=401, detail="Unauthorized")

    logger.info(f"Admin auth succeeded for {path} from {client_host}")
