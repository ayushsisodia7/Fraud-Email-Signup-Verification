from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.api.v1.endpoints import router as api_router, set_risk_engine
from app.api.v1.admin import router as admin_router
from app.core.config import settings
from app.core.logging import setup_logging, get_logger
from app.services.risk_engine import RiskEngine
import os

# Initialize logging
setup_logging()
logger = get_logger("main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Application starting up...")
    
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

