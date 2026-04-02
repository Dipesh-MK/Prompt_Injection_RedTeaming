# schemas/victim.py
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional

class VictimConfig(BaseModel):
    ollama_url: str = Field(default="http://localhost:11434/api/generate", description="Ollama base URL")
    victim_model: str = Field(default="gemmaSecure:latest", description="Victim model name")
    judge_model: str = Field(default="mistral-nemo:latest", description="Judge model name")
    timeout: int = Field(default=120, description="Timeout in seconds")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "ollama_url": "http://localhost:11434/api/generate",
                "victim_model": "gemmaSecure:latest"
            }
        }
    )