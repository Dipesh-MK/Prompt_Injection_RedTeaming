# database.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from config import settings

# Create engine with good settings for local PostgreSQL
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,           # helps with connection drops
    pool_size=10,
    max_overflow=20,
    echo=False                    # Set to True for debugging SQL
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

print("✅ Database engine initialized successfully.")