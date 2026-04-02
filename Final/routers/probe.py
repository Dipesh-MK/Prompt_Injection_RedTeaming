# routers/probe.py
from fastapi import APIRouter, BackgroundTasks
from services.probe_service import ProbeService
from schemas.probe import ProbeSessionStatus
from schemas.scope import ScopeCreate

router = APIRouter(prefix="/probes", tags=["Probes"])

# Need to keep track of concurrent probe sessions or use a single global session for this MVP
probe_service = ProbeService()

@router.post("/start", response_model=ProbeSessionStatus)
async def start_probe_session(scope: ScopeCreate, background_tasks: BackgroundTasks):
    """Start a new probe session asynchronously"""
    # Reset memory/probes array if we start a new session inside the same process
    # This ensures a "fresh" start from the GUI
    global probe_service
    probe_service = ProbeService()
    
    background_tasks.add_task(
        probe_service.run_probe_session,
        scope.scope_text, 
        40,  # Max probes default for GUI mode
        scope.target_endpoint
    )
    
    # Return immediately
    return ProbeSessionStatus(
        session_id=probe_service.session_id,
        total_probes=0,
        criteria_covered_count=0,
        coverage_percentage=0.0,
        weak_areas=[],
        strong_areas=[],
        is_complete=False,
        probes=[]
    )

@router.get("/status", response_model=ProbeSessionStatus)
async def get_probe_status():
    """Get current session status remotely polled by GUI"""
    summary = probe_service.memory.get_summary()
    return ProbeSessionStatus(
        session_id=probe_service.session_id,
        total_probes=len(probe_service.probes),
        criteria_covered_count=summary["criteria_covered_count"],
        coverage_percentage=summary["coverage_percentage"],
        weak_areas=summary["weak_areas"],
        strong_areas=summary["strong_areas"],
        is_complete=(len(probe_service.probes) >= 40), # Dummy complete tracker
        probes=probe_service.probes
    )