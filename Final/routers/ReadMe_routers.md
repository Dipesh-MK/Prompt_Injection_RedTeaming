# Routers Control Plane
This module organizes the HTTP REST endpoints into semantic blocks so `main.py` simply manages a cleanly routed topology.

### Files Explained:
- **`main_router.py`**: A composite router that recursively aggregates all other sub-routers before being mounted by the core `FastAPI` instance.
- **`probe.py`**: Defines the `/probes/start` and `/probes/status` endpoints. It safely pushes long-running LLM generation requests into `BackgroundTasks` to prevent thread hanging.
- **`mutation.py`**: Exposes `/mutation/run` for clients interacting directly with the adversarial prompt rewriting sequence.
