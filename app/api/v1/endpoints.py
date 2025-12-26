from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Annotated

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
    risk_summary: dict
    signals: dict

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
