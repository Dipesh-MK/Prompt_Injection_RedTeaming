# Final Directory Backend Application
The `Final/` directory is the core of the RedTeamForge product! It encapsulates the FastAPI server, configuration pipeline, and the embedded Web UI.

### Key Files:
- **`main.py`**: The entrypoint for the FastAPI application. Mounts the router hierarchy, serves the custom HTML frontend, and initializes middleware.
- **`config.py`**: Utilizes Pydantic's `SettingsConfigDict` to securely source environment variables and local defaults (e.g. `OLLAMA_URL`, model hashes).
- **`database.py`**: Instantiates the SQLAlchemy engine mapped to the PostgreSQL server allowing connections from various services.
- **`requirements.txt`**: Records the exact Python dependencies required to boot the application.
- **`routers/`**: Directory tracking all API endpoint controllers.
- **`schemas/`**: Directory enforcing Request/Response data integrity.
- **`services/`**: Directory housing the complex local LLM orchestrations.
- **`static/`**: Directly serves the browser-facing Vue-less vanilla Javascript dashboard.
