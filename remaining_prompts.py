from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

DB_URI = "postgresql://postgres:Aracknab420697!?@localhost:5432/redteam"
engine = create_engine(DB_URI, poolclass=NullPool)

with engine.begin() as conn:
    result = conn.execute(text("""
        UPDATE evaluated_prompts
        SET success_flag         = NULL,
            leak_type            = NULL,
            severity_score       = NULL,
            evaluator_version    = NULL,
            evaluation_timestamp = NULL
    """))
    print(f"Reset {result.rowcount} rows -- ready for full re-evaluation")

with engine.connect() as conn:
    unevaluated = conn.execute(text("SELECT COUNT(*) FROM evaluated_prompts WHERE success_flag IS NULL")).scalar()
    print(f"Rows queued for evaluation: {unevaluated}")