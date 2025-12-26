from contextlib import asynccontextmanager
from uuid import uuid4
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from app.api.v1.endpoints import router as api_router, set_risk_engine
from app.api.v1.admin import router as admin_router
from app.core.config import settings
from app.core.logging import setup_logging, get_logger, request_id_ctx_var
from app.core.metrics import HTTP_REQUESTS_TOTAL, HTTP_REQUEST_LATENCY_SECONDS, normalize_path
from app.services.risk_engine import RiskEngine
import os

# Initialize logging
setup_logging()
logger = get_logger("main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Application starting up...")

    # Fail fast on missing secrets in non-dev environments
    if (settings.ENVIRONMENT or "dev").lower() != "dev":
        if not (settings.ADMIN_API_KEY or "").strip():
            raise RuntimeError("ADMIN_API_KEY must be set in non-dev environments")
    
    # Initialize RiskEngine and its Redis connection
    risk_engine_instance = RiskEngine()
    
    # Inject into endpoints
    set_risk_engine(risk_engine_instance)
    
    # Initial fetch of disposable domains
    count = await risk_engine_instance.domain_manager.update_disposable_domains()
    logger.info(f"Initialized with {count} disposable domains.")
    
    yield
    
    # Shutdown
    logger.info("Application shutting down...")
    await risk_engine_instance.close()

app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)

# Request ID middleware
class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid4())
        token = request_id_ctx_var.set(request_id)
        try:
            response = await call_next(request)
        finally:
            request_id_ctx_var.reset(token)
        response.headers["X-Request-ID"] = request_id
        return response

app.add_middleware(RequestIdMiddleware)

# Prometheus HTTP metrics middleware
class PrometheusMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        method = request.method
        # Middleware runs before routing, so normalize known dynamic paths ourselves.
        path = normalize_path(request.url.path)

        with HTTP_REQUEST_LATENCY_SECONDS.labels(method=method, path=path).time():
            response = await call_next(request)

        HTTP_REQUESTS_TOTAL.labels(method=method, path=path, status=str(response.status_code)).inc()
        return response

app.add_middleware(PrometheusMiddleware)

# Include API routers
app.include_router(api_router, prefix=settings.API_V1_STR)
app.include_router(admin_router, prefix=f"{settings.API_V1_STR}/admin", tags=["Admin"])

# Serve dashboard
@app.get("/dashboard")
async def serve_dashboard():
    dashboard_path = os.path.join(os.path.dirname(__file__), "app/dashboard/index.html")
    return FileResponse(dashboard_path)

@app.get("/")
async def root():
    return {
        "message": "Fraud Email Signup Verification API",
        "docs": "/docs",
        "dashboard": "/dashboard"
    }

@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

