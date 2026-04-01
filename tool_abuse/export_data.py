"""
export_data.py
──────────────
Exports prompt + evaluation data to a JSON file for the HTML dashboard.
Queries the local `redteam_db` PostgreSQL database directly, pulling from
the `attack_prompts`, `attack_runs`, and `tools` tables.

Usage:
    python3 export_data.py
"""

import sys
sys.stdout.reconfigure(encoding='utf-8')

import json
from datetime import datetime, timezone
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

# Connect to the local MacOS postgres instance and redteam_db
DB_URI = "postgresql://incharakandgal@localhost:5432/redteam_db"
OUTPUT_FILE = "dashboard_data.js"

engine = create_engine(DB_URI, poolclass=NullPool)

print("Querying database redteam_db...")

with engine.connect() as conn:
    rows = conn.execute(text("""
        SELECT
            p.id::text               AS prompt_id,
            p.prompt_text,
            p.vector                 AS attack_technique,
            t.name                   AS tool_call_type,
            p.injected_payload,
            r.id::text               AS eval_id,
            r.llm_response           AS llm_output,
            r.target_model           AS model_name,
            r.success_flag,
            r.leak_type              AS attack_category,
            r.severity_score,
            r.run_at::text           AS run_timestamp
        FROM attack_prompts p
        LEFT JOIN attack_runs r ON r.prompt_id = p.id
        LEFT JOIN tools t ON p.target_tool_id = t.id
        ORDER BY r.severity_score DESC NULLS LAST
    """)).fetchall()

columns = [
    "prompt_id", "prompt_text", "attack_technique", "tool_call_type",
    "injected_payload", "eval_id", "llm_output", "model_name",
    "success_flag", "attack_category", "severity_score", "run_timestamp"
]

records = []
for row in rows:
    record = {}
    for i, col in enumerate(columns):
        val = row[i]
        if val is None:
            record[col] = None
        elif isinstance(val, float):
            record[col] = round(val, 4)
        else:
            record[col] = str(val) if not isinstance(val, (bool, int, float)) else val
            
    # Add dummy fields for UI compatibility if needed
    record["confidence"] = None
    record["inference_time_sec"] = None
    record["evaluator_version"] = "v2_tool_abuse"
    
    records.append(record)

output = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "total_records": len(records),
    "records": records
}

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    f.write("window.DASHBOARD_DATA = ")
    json.dump(output, f, ensure_ascii=False, indent=2)
    f.write(";\n")

print(f"Exported {len(records)} records → {OUTPUT_FILE}")
print("Done. You can now open tool_abuse_dashboard.html in your browser.")
