from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.api.v1.endpoints import router as api_router, set_risk_engine
from app.core.config import settings
from app.core.logging import setup_logging, get_logger
from app.services.risk_engine import RiskEngine

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

app.include_router(api_router, prefix=settings.API_V1_STR)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
