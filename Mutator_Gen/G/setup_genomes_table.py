# setup_genomes_table.py
from sqlalchemy import create_engine, Column, String, Integer, JSON, DateTime
from sqlalchemy.orm import declarative_base
from datetime import datetime
import sys

# Force UTF-8 output on Windows (fixes your previous emoji error)
sys.stdout.reconfigure(encoding='utf-8')

# ================== YOUR CONFIG ==================
DB_URI = "postgresql://postgres:Aracknab420697!?@localhost:5432/redteam"   # ← CHANGE THIS LINE

engine = create_engine(DB_URI, echo=False)
Base = declarative_base()

class Genome(Base):
    __tablename__ = "genomes"
    
    genome_id = Column(String, primary_key=True)
    prompt_id = Column(String)
    technique = Column(String)
    persona = Column(String)
    framing = Column(String)
    encoding = Column(String)
    language = Column(String)
    nesting_depth = Column(Integer)
    structure = Column(String)
    complexity_score = Column(Integer)
    features_json = Column(JSON)           # Dynamic new features stored here
    parent_genome = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(engine)
print("SUCCESS: genomes table created (or already existed) in redteam DB")
print("You can now run test_generators.py")