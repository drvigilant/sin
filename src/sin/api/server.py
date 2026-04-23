from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, Optional

from sin.utils.logger import get_logger
from sin.agent.runner import AgentRunner

logger = get_logger("sin.api.server")
app = FastAPI(title="SIN Enterprise API")

class ScanRequest(BaseModel):
    subnet: Optional[str] = None

def run_scan_job(subnet: str):
    """
    Executes the exact same logic as your CLI main.py, 
    but running as a direct background thread of the API.
    """
    logger.info(f"Starting background scan for {subnet}")
    try:
        runner = AgentRunner()
        runner.run_assessment(subnet=subnet)
        logger.info("Background scan completed successfully.")
    except Exception as e:
        logger.error(f"Background scan crashed: {e}")

@app.post("/scan/trigger")
def trigger_network_scan(request: ScanRequest, background_tasks: BackgroundTasks) -> Dict:
    target = request.subnet or "192.168.30"
    logger.info(f"API received scan command from Dashboard for: {target}")
    
    try:
        # Bypass Celery entirely and use FastAPI's native background task manager
        background_tasks.add_task(run_scan_job, target)
        
        return {
            "status": "success", 
            "message": "Scan dispatched directly to backend engine."
        }
    except Exception as e:
        logger.error(f"Failed to dispatch scan via API: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health_check():
    return {"status": "online", "api": "SIN Enterprise"}
