# config.py
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql://postgres:Aracknab420697!?@localhost:5432/redteam"
    
    # Ollama Base URL
    OLLAMA_URL: str = "http://localhost:11434/api/generate"
    
    # Default models (can be overridden from GUI/API)
    DEFAULT_VICTIM_MODEL: str = "gemmaSecure:latest"
    JUDGE_MODEL: str = "mistral-nemo:latest"
    
    # Timeouts
    OLLAMA_TIMEOUT: int = 120
    DEFAULT_MAX_PROBES: int = 30
    MAX_SESSION_TIME_MINUTES: int = 45
    
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()