import pandas as pd
import glob
import uuid
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool
from datetime import datetime, timezone

DB_URI = "postgresql://postgres:Aracknab420697!?@localhost:5432/redteam"

engine = create_engine(DB_URI, poolclass=NullPool)

total_prompts_inserted    = 0
total_evaluated_inserted  = 0
total_skipped             = 0

# =========================
# HELPER
# =========================

def insert_prompt(conn, prompt_id, prompt_text, has_been_run=True, label=None):
    conn.execute(text("""
        INSERT INTO prompts (id, prompt_text, label, has_been_run, created_at)
        VALUES (:id, :prompt_text, :label, :has_been_run, :created_at)
        ON CONFLICT (id) DO NOTHING
    """), {
        "id":           prompt_id,
        "prompt_text":  prompt_text,
        "label":        label,
        "has_been_run": has_been_run,
        "created_at":   datetime.now(timezone.utc)
    })


def insert_evaluated(conn, prompt_id, row, has_evaluation=False):
    conn.execute(text("""
        INSERT INTO evaluated_prompts (
            id, prompt_id, llm_output, inference_time_sec,
            model_name, timestamp,
            leak_type, severity_score, success_flag,
            evaluator_version, evaluation_timestamp, created_at
        ) VALUES (
            gen_random_uuid(), :prompt_id, :llm_output, :inference_time_sec,
            :model_name, :timestamp,
            :leak_type, :severity_score, :success_flag,
            :evaluator_version, :evaluation_timestamp, :created_at
        )
        ON CONFLICT (prompt_id) DO NOTHING
    """), {
        "prompt_id":            prompt_id,
        "llm_output":           str(row.get("llm_output", "")),
        "inference_time_sec":   float(row.get("inference_time_sec", 0) or 0),
        "model_name":           str(row.get("model_name", "")),
        "timestamp":            str(row.get("timestamp", "")),
        "leak_type":            row.get("leak_type") if has_evaluation and pd.notna(row.get("leak_type")) else None,
        "severity_score":       float(row["severity_score"]) if has_evaluation and pd.notna(row.get("severity_score")) else None,
        "success_flag":         bool(row["success_flag"]) if has_evaluation and pd.notna(row.get("success_flag")) else None,
        "evaluator_version":    str(row["evaluator_version"]) if has_evaluation and pd.notna(row.get("evaluator_version")) else None,
        "evaluation_timestamp": str(row["evaluation_timestamp"]) if has_evaluation and pd.notna(row.get("evaluation_timestamp")) else None,
        "created_at":           datetime.now(timezone.utc)
    })

# =========================
# STEP 1: llm_outputs_1000_evaluated (best source for first 1000)
# =========================

print("=" * 60)
print("Importing llm_outputs_1000_evaluated.xlsx (with evaluation data)...")

df = pd.read_excel("llm_outputs_1000_evaluated.xlsx")
inserted = 0
skipped  = 0

with engine.begin() as conn:
    for _, row in df.iterrows():
        new_id      = str(uuid.uuid4())
        prompt_text = str(row["prompt"]).strip()

        insert_prompt(conn, new_id, prompt_text, has_been_run=True,
                      label=str(row["leak_type"]) if pd.notna(row.get("leak_type")) else None)
        insert_evaluated(conn, new_id, row, has_evaluation=True)
        inserted += 1

print(f"  Inserted : {inserted} rows")
total_prompts_inserted   += inserted
total_evaluated_inserted += inserted

# =========================
# STEP 2: Batch files (inference only)
# =========================

print("\nImporting batch files...")

batch_files = sorted(glob.glob("batches/batch_*.xlsx"))
print(f"  Found {len(batch_files)} batch files\n")

for file in batch_files:
    df       = pd.read_excel(file)
    inserted = 0
    skipped  = 0

    with engine.begin() as conn:
        for _, row in df.iterrows():
            new_id      = str(uuid.uuid4())
            prompt_text = str(row["prompt_text"]).strip()

            insert_prompt(conn, new_id, prompt_text, has_been_run=True)
            insert_evaluated(conn, new_id, row, has_evaluation=False)
            inserted += 1

    print(f"  {file} -- {inserted} inserted, {skipped} skipped")
    total_prompts_inserted   += inserted
    total_evaluated_inserted += inserted

# =========================
# STEP 3: Add remaining unrun prompts to remaining_prompts table
# (so inference script knows what's left)
# =========================

print("\nPopulating remaining_prompts for unrun prompts...")

with engine.begin() as conn:
    conn.execute(text("""
        INSERT INTO remaining_prompts (id, prompt_id, created_at)
        SELECT gen_random_uuid(), id, NOW()
        FROM prompts
        WHERE has_been_run = FALSE
        ON CONFLICT DO NOTHING
    """))

# =========================
# SUMMARY
# =========================

print("\n" + "=" * 60)
with engine.connect() as conn:
    prompts_count   = conn.execute(text("SELECT COUNT(*) FROM prompts")).scalar()
    evaluated_count = conn.execute(text("SELECT COUNT(*) FROM evaluated_prompts")).scalar()
    remaining_count = conn.execute(text("SELECT COUNT(*) FROM remaining_prompts")).scalar()
    run_count       = conn.execute(text("SELECT COUNT(*) FROM prompts WHERE has_been_run = TRUE")).scalar()

    print(f"Total prompts inserted    : {prompts_count}")
    print(f"Already run               : {run_count}")
    print(f"Evaluated rows            : {evaluated_count}")
    print(f"Remaining in queue        : {remaining_count}")
    print(f"\nAll data imported successfully!")