# routers/mutation.py
from fastapi import APIRouter
from services.mutator_service import MutatorService
from schemas.mutation import MutationStatus
from schemas.scope import ScopeCreate
from typing import Dict, Any

router = APIRouter(prefix="/mutation", tags=["Mutation Engine"])

mutator_service = MutatorService()

@router.post("/run", response_model=MutationStatus)
async def run_mutation_engine(scope: ScopeCreate, num_prompts: int = 5):
    """
    Run the mutation engine based on the scope and send outputs to target endpoint.
    In a real scenario, this would also take the memory summary.
    For this API, we will just pass a placeholder or trigger it globally.
    """
    
    dummy_memory = {
        "weak_areas": ["role play", "system instruction override"],
        "coverage_percentage": 50.0
    }
    
    result = await mutator_service.run_mutation(
        scope_text=scope.scope_text, 
        memory_summary=dummy_memory, 
        num_children=num_prompts,
        target_endpoint=scope.target_endpoint
    )
    
    return MutationStatus(
        num_generated=result["num_generated"],
        message=result["message"],
        generated_prompts=result["generated_prompts"]
    )
