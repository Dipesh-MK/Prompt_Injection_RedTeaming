# schemas/mutation.py
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional

class MutationStatus(BaseModel):
    num_generated: int
    message: str
    generated_prompts: List[dict] = Field(default_factory=list)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "num_generated": 10,
                "message": "Mutation completed"
            }
        }
    )
