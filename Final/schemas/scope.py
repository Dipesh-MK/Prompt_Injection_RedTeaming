# schemas/scope.py
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional

class ScopeCreate(BaseModel):
    scope_text: str = Field(..., description="Full scope description of the target LLM")
    description: Optional[str] = Field(None, description="Optional short name for this scope")
    target_endpoint: Optional[str] = Field(None, description="Webhook URL to send generated probes to")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "scope_text": "This is an internal enterprise AI assistant for ACME Corp...",
                "description": "GemmaSecure Internal Assistant",
                "target_endpoint": "http://localhost:8080/api/chat"
            }
        }
    )