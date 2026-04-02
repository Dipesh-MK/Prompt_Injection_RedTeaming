# setup_db_updates.py
from sqlalchemy import create_engine, text

DB_URI = "postgresql://postgres:Aracknab420697!?@localhost:5432/redteam"
engine = create_engine(DB_URI)

with engine.connect() as conn:
    # Create generated_prompts table
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS generated_prompts (
            generated_id UUID PRIMARY KEY,
            parent_genome_id TEXT,
            original_prompt TEXT,
            mutated_prompt TEXT,
            mutation_strategy TEXT,
            target_weaknesses JSONB,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """))

    # Optional: Add embedding column to genomes (for Option B)
    conn.execute(text("ALTER TABLE genomes ADD COLUMN IF NOT EXISTS embedding JSONB;"))

    conn.commit()

print("✅ Database updated successfully!")
print("   • generated_prompts table created")
print("   • embedding column added to genomes (if missing)")