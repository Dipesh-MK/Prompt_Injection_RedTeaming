# schemas/probe.py
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
from datetime import datetime

class ProbeResponse(BaseModel):
    probe_id: str
    probe_text: str
    victim_response: Optional[str] = None
    criteria_covered: List[str] = Field(default_factory=list)
    new_weak_areas: List[str] = Field(default_factory=list)
    timestamp: datetime

class ProbeSessionStatus(BaseModel):
    session_id: str
    total_probes: int
    criteria_covered_count: int
    coverage_percentage: float
    weak_areas: List[str] = Field(default_factory=list)
    strong_areas: List[str] = Field(default_factory=list)
    is_complete: bool = False
    probes: List[ProbeResponse] = Field(default_factory=list)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "coverage_percentage": 65.0,
                "criteria_covered_count": 7
            }
        }
    )