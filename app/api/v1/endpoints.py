from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.core.config import settings
from app.services.enrichment_queue import enqueue_job, store_result, get_result

# We need to import the dependency logic. 
# Since get_risk_engine is in main.py, avoiding circular imports is tricky.
# Standard pattern: Move dependency to a dependencies.py or keep RiskEngine in a singleton.
# Let's create a simple dependencies module.
# But for now, I will modify main.py to NOT contain the implementation of get_risk_engine if possible,
# or better, move initialization to services.

from app.services.risk_engine import RiskEngine

router = APIRouter()

# Placeholder for dependency injection. 
# In a real app, I'd move 'risk_engine_instance' to a separate state container.
# For simplicity, we will assume the app state or a singleton pattern in risk_engine.py could work,
# but the current main.py defines the global.
# Let's use FastAPI's Request.app.state if we attached it there, or just use a shared singleton module.

# Refactoring:
# A common pattern is to have a variable in a module that is initialized.
# Let's use a lazy/global variable in endpoints for now, injected by main.

_risk_engine: RiskEngine = None

def get_risk_engine():
    if _risk_engine is None:
        raise HTTPException(status_code=503, detail="Service not initialized")
    return _risk_engine

def set_risk_engine(engine: RiskEngine):
    global _risk_engine
    _risk_engine = engine

class AnalyzeRequest(BaseModel):
    email: str
    ip_address: str
    user_agent: str
    
class AnalyzeResponse(BaseModel):
    email: str
    normalized_email: str
    reasons: list[dict]
    risk_summary: dict
    signals: dict

class EnrichmentInfo(BaseModel):
    job_id: str | None = None
    status: str  # PENDING|COMPLETE|DISABLED

class AnalyzeFastResponse(AnalyzeResponse):
    enrichment: EnrichmentInfo

@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_email(
    request: AnalyzeRequest,
):
    engine = get_risk_engine()
    try:
        result = await engine.analyze(request.email, request.ip_address, request.user_agent)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # Log generic error (handled in risk_engine logging already)
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.post("/analyze/fast", response_model=AnalyzeFastResponse)
async def analyze_email_fast(request: AnalyzeRequest):
    engine = get_risk_engine()
    try:
        result = await engine.analyze_fast(request.email, request.ip_address, request.user_agent)

        if not settings.ENABLE_BACKGROUND_ENRICHMENT:
            result["enrichment"] = {"job_id": None, "status": "DISABLED"}
            return result

        job_id = await enqueue_job(engine.redis, {
            "email": request.email,
            "ip_address": request.ip_address,
            "user_agent": request.user_agent,
        })

        # Store base result immediately (so polling returns something)
        result["enrichment"] = {"job_id": job_id, "status": "PENDING"}
        await store_result(engine.redis, job_id, result)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.get("/results/{job_id}")
async def get_analysis_result(job_id: str):
    engine = get_risk_engine()
    result = await get_result(engine.redis, job_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Result not found")
    return result
