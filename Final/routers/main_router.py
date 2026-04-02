# routers/main_router.py
from fastapi import APIRouter
from routers.probe import router as probe_router
from routers.mutation import router as mutation_router

main_router = APIRouter()

main_router.include_router(probe_router)
main_router.include_router(mutation_router)