import sys
sys.stdout.reconfigure(encoding='utf-8')
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool
from sqlalchemy.exc import OperationalError
import pandas as pd
import requests
import time
from datetime import datetime, timezone
import os
import uuid

# =========================
# CONFIG
# =========================

DB_URI = "postgresql://postgres.zxctsprcaoxscpioamdf:spandyisgay!@aws-1-ap-southeast-2.pooler.supabase.com:6543/postgres?sslmode=require"
MODEL_NAME = "gemmaSecure"
OLLAMA_URL = "http://localhost:11434/api/generate"
REQUEST_TIMEOUT = 120
MAX_RETRIES = 2
TOTAL_LIMIT = 5000
BATCH_SIZE = 500
OUTPUT_DIR = "batches"

os.makedirs(OUTPUT_DIR, exist_ok=True)

# =========================
# ENGINE
# =========================

engine = create_engine(
    DB_URI,
    poolclass=NullPool,
    connect_args={
        "connect_timeout": 30,
        "keepalives": 1,
        "keepalives_idle": 10,
        "keepalives_interval": 5,
        "keepalives_count": 5,
        "sslmode": "require"
    }
)

# =========================
# DB HELPER WITH RETRY
# =========================

def execute_with_retry(query, params=None, retries=3, fetch=True):
    for attempt in range(retries):
        try:
            with engine.connect() as conn:
                result = conn.execute(text(query), params or {})
                if fetch:
                    return result.fetchall()
                return None
        except OperationalError as e:
            print(f"  [DB] Connection failed (attempt {attempt+1}/{retries}): {e}")
            time.sleep(3)
    raise Exception("DB connection failed after all retries.")

# =========================
# STEP 1: FETCH REMAINING PROMPTS
# =========================

print("Checking remaining_prompts table...")
remaining_count = execute_with_retry("SELECT COUNT(*) FROM remaining_prompts")[0][0]
print(f"  remaining_prompts has {remaining_count} entries")

print("\nFetching unrun prompts...")

if remaining_count > 0:
    rows = execute_with_retry("""
        SELECT p.id, p.prompt_text
        FROM prompts p
        INNER JOIN remaining_prompts rp ON rp.prompt_id = p.id
        WHERE p.has_been_run = FALSE
        AND p.id NOT IN (SELECT prompt_id FROM evaluated_prompts WHERE prompt_id IS NOT NULL)
        ORDER BY p.created_at
        LIMIT :limit
    """, {"limit": TOTAL_LIMIT})
else:
    print("  remaining_prompts is empty -- falling back to prompts table directly...")
    rows = execute_with_retry("""
        SELECT id, prompt_text
        FROM prompts
        WHERE has_been_run = FALSE
        AND id NOT IN (SELECT prompt_id FROM evaluated_prompts WHERE prompt_id IS NOT NULL)
        ORDER BY created_at
        LIMIT :limit
    """, {"limit": TOTAL_LIMIT})

print(f"Found {len(rows)} unrun prompts to process.\n")

if not rows:
    print("No remaining prompts found. All done!")
    exit()

# =========================
# STEP 2: FIGURE OUT STARTING BATCH NUMBER
# =========================

existing_batches = [
    f for f in os.listdir(OUTPUT_DIR)
    if f.startswith("batch_") and f.endswith(".xlsx")
]
batch_num = len(existing_batches) + 1
print(f"  Starting at batch number: {batch_num}\n")

# =========================
# STEP 3: INFERENCE
# =========================

def run_inference(prompt_text):
    for attempt in range(MAX_RETRIES + 1):
        try:
            start = time.time()
            response = requests.post(
                OLLAMA_URL,
                json={"model": MODEL_NAME, "prompt": prompt_text, "stream": False},
                timeout=REQUEST_TIMEOUT
            )
            elapsed = round(time.time() - start, 3)

            if response.status_code == 200:
                return response.json().get("response", ""), elapsed
            else:
                print(f"  HTTP {response.status_code}, retrying ({attempt+1}/{MAX_RETRIES})...")

        except Exception as e:
            print(f"  Error: {e}, retrying ({attempt+1}/{MAX_RETRIES})...")
            time.sleep(2)

    return "FAILED AFTER RETRIES", -1

# =========================
# STEP 4: SAVE FUNCTIONS
# =========================

def save_batch_to_excel(batch_results, batch_num):
    df = pd.DataFrame(batch_results)
    filename = os.path.join(OUTPUT_DIR, f"batch_{batch_num:03d}_{MODEL_NAME}.xlsx")

    if os.path.exists(filename):
        timestamp_str = datetime.now().strftime("%H%M%S")
        filename = os.path.join(OUTPUT_DIR, f"batch_{batch_num:03d}_{MODEL_NAME}_{timestamp_str}.xlsx")

    df.to_excel(filename, index=False)
    print(f"\n  Batch {batch_num} saved >> {filename}\n")
    return filename


def mark_prompts_as_run(prompt_ids):
    """Update has_been_run = TRUE and remove from remaining_prompts."""
    uuid_ids = [uuid.UUID(pid) if isinstance(pid, str) else pid for pid in prompt_ids]

    for attempt in range(3):
        try:
            with engine.begin() as conn:
                conn.execute(text("""
                    UPDATE prompts
                    SET has_been_run = TRUE
                    WHERE id = ANY(:ids)
                """), {"ids": uuid_ids})

                conn.execute(text("""
                    DELETE FROM remaining_prompts
                    WHERE prompt_id = ANY(:ids)
                """), {"ids": uuid_ids})
            return
        except OperationalError as e:
            print(f"  [DB] mark_prompts_as_run failed (attempt {attempt+1}/3): {e}")
            time.sleep(3)
    print("  WARNING: Could not mark prompts as run -- they may re-run next time!")


def save_batch_to_db(batch_results):
    """Insert results into evaluated_prompts. ON CONFLICT skips duplicates fast."""
    for attempt in range(3):
        try:
            with engine.begin() as conn:
                for r in batch_results:
                    conn.execute(text("""
                        INSERT INTO evaluated_prompts (
                            id, prompt_id, llm_output, inference_time_sec,
                            model_name, timestamp, created_at
                        ) VALUES (
                            gen_random_uuid(), :prompt_id, :llm_output,
                            :inference_time_sec, :model_name, :timestamp, :created_at
                        )
                        ON CONFLICT (prompt_id) DO NOTHING
                    """), {
                        "prompt_id":          r["prompt_id"],
                        "llm_output":         r["llm_output"],
                        "inference_time_sec": r["inference_time_sec"],
                        "model_name":         r["model_name"],
                        "timestamp":          r["timestamp"],
                        "created_at":         datetime.now(timezone.utc)
                    })
            return
        except OperationalError as e:
            print(f"  [DB] save_batch_to_db failed (attempt {attempt+1}/3): {e}")
            time.sleep(3)
    print("  WARNING: Could not save batch to DB -- check Excel backup!")

# =========================
# MAIN LOOP
# =========================

current_batch = []
total_processed = 0
batch_prompt_ids = []

print(f"Starting processing -- {len(rows)} prompts, batches of {BATCH_SIZE}\n")
print("=" * 60)

for idx, row in enumerate(rows, start=1):
    prompt_id = str(row[0])
    prompt_text = row[1]

    print(f"[{idx}/{len(rows)}] Running prompt {prompt_id[:8]}...")

    llm_output, inference_time = run_inference(prompt_text)

    status = "OK" if inference_time != -1 else "FAILED"
    print(f"  >> {status} | {inference_time}s")

    current_batch.append({
        "prompt_id":          prompt_id,
        "prompt_text":        prompt_text,
        "llm_output":         llm_output,
        "inference_time_sec": inference_time,
        "model_name":         MODEL_NAME,
        "timestamp":          datetime.now(timezone.utc).isoformat(),
    })
    batch_prompt_ids.append(prompt_id)
    total_processed += 1

    if len(current_batch) >= BATCH_SIZE:
        print(f"\nBatch {batch_num} complete ({BATCH_SIZE} prompts). Saving...")
        save_batch_to_excel(current_batch, batch_num)
        save_batch_to_db(current_batch)
        mark_prompts_as_run(batch_prompt_ids)

        current_batch = []
        batch_prompt_ids = []
        batch_num += 1

# Save final partial batch
if current_batch:
    print(f"\nFinal batch ({len(current_batch)} prompts). Saving...")
    save_batch_to_excel(current_batch, batch_num)
    save_batch_to_db(current_batch)
    mark_prompts_as_run(batch_prompt_ids)

# =========================
# SUMMARY
# =========================

print("\n" + "=" * 60)
print(f"Done! Total processed this run : {total_processed}")
print(f"Batches saved to               : ./{OUTPUT_DIR}/")

try:
    remaining_left  = execute_with_retry("SELECT COUNT(*) FROM remaining_prompts")[0][0]
    evaluated_total = execute_with_retry("SELECT COUNT(*) FROM evaluated_prompts")[0][0]
    print(f"Prompts still remaining in DB  : {remaining_left}")
    print(f"Total evaluated in DB          : {evaluated_total}")
except Exception as e:
    print(f"Could not fetch final counts: {e}")