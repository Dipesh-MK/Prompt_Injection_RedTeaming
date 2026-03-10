from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

DB_URI = "postgresql://postgres:Aracknab420697!?@localhost:5432/redteam"
engine = create_engine(DB_URI, poolclass=NullPool)

with engine.connect() as conn:
    total      = conn.execute(text("SELECT COUNT(*) FROM evaluated_prompts")).scalar()
    evaluated  = conn.execute(text("SELECT COUNT(*) FROM evaluated_prompts WHERE success_flag IS NOT NULL")).scalar()
    unevaluated= conn.execute(text("SELECT COUNT(*) FROM evaluated_prompts WHERE success_flag IS NULL")).scalar()
    failed     = conn.execute(text("SELECT COUNT(*) FROM evaluated_prompts WHERE llm_output = 'FAILED AFTER RETRIES'")).scalar()

    print(f"Total rows in evaluated_prompts : {total}")
    print(f"Already has success_flag        : {evaluated}  <- will be SKIPPED")
    print(f"Needs evaluation (NULL)         : {unevaluated} <- will be PROCESSED")
    print(f"Failed inference (skipped)      : {failed}")
    print(f"\nEvaluator will process          : {unevaluated - failed} prompts")