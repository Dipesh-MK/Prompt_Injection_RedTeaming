# main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from config import settings
from routers.main_router import main_router
import uvicorn

app = FastAPI(
    title="RedTeamForge - LLM Red Teaming Platform",
    description="Autonomous LLM Security Testing Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(main_router)

# Mount the static files for the dashboard
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def root():
    # Redirect base to the GUI dashboard automatically
    return RedirectResponse(url="/static/index.html")

@app.get("/api/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)