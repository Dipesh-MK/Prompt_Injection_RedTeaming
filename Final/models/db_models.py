from sqlalchemy import Column, Integer, String, Text, Float, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from database import Base
import datetime

class SessionDB(Base):
    __tablename__ = "sessions"
    session_id = Column(String, primary_key=True)
    scope_text = Column(Text)
    webhook_url = Column(Text)
    start_time = Column(DateTime, default=datetime.datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    total_probes = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)

class ProbeDispatchDB(Base):
    __tablename__ = "probe_dispatches"
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String, ForeignKey("sessions.session_id"))
    probe_text = Column(Text)
    webhook_url = Column(Text)
    dispatched_at = Column(DateTime, default=datetime.datetime.utcnow)
    response_received_at = Column(DateTime, nullable=True)
    victim_response = Column(Text, nullable=True)
    judgment = Column(JSON, nullable=True)
    severity = Column(Integer, nullable=True)
    status = Column(String)  # 'pending', 'in_flight', 'judged', 'failed'

class GenomeDB(Base):
    __tablename__ = "genomes"
    id = Column(Integer, primary_key=True, autoincrement=True)
    genome_id = Column(String, unique=True, index=True)
    prompt_text = Column(Text)
    technique = Column(String)
    persona = Column(String, default='none')
    framing = Column(String)
    encoding = Column(String)
    nesting_depth = Column(Integer)
    complexity_score = Column(Float)
    features_json = Column(JSON, nullable=True)
    
    # New columns
    parent_id = Column(Integer, ForeignKey("genomes.id"), nullable=True)
    severity_score = Column(Float, default=0.0)
    persona_tag = Column(String, nullable=True)
    
class GeneratedPromptDB(Base):
    __tablename__ = "generated_prompts"
    id = Column(Integer, primary_key=True, autoincrement=True)
    generated_id = Column(String, unique=True, index=True)
    parent_genome_id = Column(String) # matches genome_id string for backwards compat
    original_prompt = Column(Text)
    mutated_prompt = Column(Text)
    mutation_strategy = Column(String)
    target_weaknesses = Column(Text) # Storing JSON as text
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
