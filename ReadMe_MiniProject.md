# Root Directory Overview
This directory acts as the root workspace for the "RedTeamForge" LLM Red Teaming platform pipeline. It contains historical scripts, offline inference utilities, documentation, and the primary active directories holding the complete web application.

### Important Artifacts:
- **`Final/`**: The modern, fully working production-ready FastAPI system with its frontend UI.
- **`Mutator_Gen/`**: Earlier iterations of the mutation logic and DB interaction handlers.
- **`batches/`**: Folder storing segmented `.xlsx` results from large offline evaluation runs.
- **`The Complete System Pitch.docx` & `project_report.docx`**: High-level documentation and university/project submissions.
- **`dashboard.py`, `judge_final.py`, `inference_batchwise.py`**: Legacy CLI and local Python scripts used to build the foundational heuristics before the transition to the FastAPI backend.
- **`DB_shift_postgres.py`**: Utility to migrate local offline outputs to the centralized PostgreSQL 'redteam' database.
- **`llm_outputs_1000.xlsx` & `leak_cases_only.xlsx`**: Raw output logs derived during model testing, serving as seed data.
