"""
export_data.py
──────────────
Exports prompt + evaluation data to a JSON file for the HTML dashboard.
Tries to read from the local PostgreSQL database first.
If the database or tables don't exist, it falls back to reading directly
from the `llm_outputs_1000_evaluated.xlsx` file.

Usage:
    python3 export_data.py
"""

import sys
sys.stdout.reconfigure(encoding='utf-8')

import json
import os
import pandas as pd
from datetime import datetime, timezone
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

DB_URI = "postgresql://incharakandgal@localhost:5432/postgres"
OUTPUT_FILE = "dashboard_data.json"

columns = [
    "prompt_id", "prompt_text", "label", "eval_id",
    "llm_output", "model_name", "inference_time_sec",
    "success_flag", "attack_category", "severity_score",
    "tool_call_type", "attack_technique", "confidence",
    "evaluator_version", "evaluation_timestamp", "run_timestamp"
]

records = []

def load_from_postgres():
    global records
    try:
        engine = create_engine(DB_URI, poolclass=NullPool)
        with engine.connect() as conn:
            # Check if tables exist
            table_exists = conn.execute(text(
                "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'prompts')"
            )).scalar()
            
            if not table_exists:
                return False
                
            rows = conn.execute(text("""
                SELECT
                    p.id::text            AS prompt_id,
                    p.prompt_text,
                    p.label,
                    e.id::text            AS eval_id,
                    e.llm_output,
                    e.model_name,
                    e.inference_time_sec,
                    e.success_flag,
                    e.leak_type           AS attack_category,
                    e.severity_score,
                    e.tool_call_type,
                    e.attack_technique,
                    e.confidence,
                    e.evaluator_version,
                    e.evaluation_timestamp::text,
                    e.timestamp::text     AS run_timestamp
                FROM prompts p
                LEFT JOIN evaluated_prompts e ON e.prompt_id = p.id
                ORDER BY e.severity_score DESC NULLS LAST
            """)).fetchall()

            for row in rows:
                record = {}
                for i, col in enumerate(columns):
                    val = row[i]
                    if val is None:
                        record[col] = None
                    elif isinstance(val, (int, float)) and pd.isna(val):
                        record[col] = None
                    elif isinstance(val, float):
                        record[col] = round(val, 4)
                    else:
                        record[col] = str(val) if not isinstance(val, (bool, int, float)) else val
                records.append(record)
        return True
    except Exception as e:
        print(f"Postgres load failed: {e}")
        return False

def load_from_excel():
    global records
    file_path = "llm_outputs_1000_evaluated.xlsx"
    if not os.path.exists(file_path):
        print(f"Error: {file_path} not found.")
        return False
        
    print(f"Loading data from {file_path}...")
    try:
        df = pd.read_excel(file_path)
        for _, row in df.iterrows():
            record = {
                "prompt_id": str(row.get("prompt_id", "")),
                "prompt_text": str(row.get("prompt", "")),
                "label": str(row.get("leak_type", "")) if pd.notna(row.get("leak_type")) else None,
                "eval_id": None,
                "llm_output": str(row.get("llm_output", "")),
                "model_name": str(row.get("model_name", "")),
                "inference_time_sec": round(float(row.get("inference_time_sec", 0)), 4) if pd.notna(row.get("inference_time_sec")) else None,
                "success_flag": bool(row["success_flag"]) if pd.notna(row.get("success_flag")) else None,
                "attack_category": str(row.get("leak_type", "")) if pd.notna(row.get("leak_type")) else None,
                "severity_score": float(row["severity_score"]) if pd.notna(row.get("severity_score")) else None,
                "tool_call_type": str(row.get("tool_call_type", "unknown")) if "tool_call_type" in df.columns and pd.notna(row.get("tool_call_type")) else None,
                "attack_technique": str(row.get("attack_technique", "unknown")) if "attack_technique" in df.columns and pd.notna(row.get("attack_technique")) else None,
                "confidence": float(row.get("confidence", 0)) if "confidence" in df.columns and pd.notna(row.get("confidence")) else None,
                "evaluator_version": str(row.get("evaluator_version", "")) if pd.notna(row.get("evaluator_version")) else None,
                "evaluation_timestamp": str(row.get("evaluation_timestamp", "")),
                "run_timestamp": str(row.get("timestamp", ""))
            }
            records.append(record)
        return True
    except Exception as e:
        print(f"Excel load failed: {e}")
        return False

if __name__ == "__main__":
    print("Attempting to query PostgreSQL database...")
    success = load_from_postgres()
    
    if not success:
        print("Database tables not found. Falling back to Excel file...")
        success = load_from_excel()
        
    if not success:
        print("Failed to load data from both database and Excel. Exiting.")
        sys.exit(1)

    # Sort records by severity score descending
    records.sort(key=lambda x: x["severity_score"] if x["severity_score"] is not None else -1, reverse=True)

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_records": len(records),
        "records": records
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"Exported {len(records)} records → {OUTPUT_FILE}")
    print("Done. You can now open tool_abuse_dashboard.html in your browser.")
