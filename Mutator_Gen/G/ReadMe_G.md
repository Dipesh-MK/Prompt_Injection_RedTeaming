# Database Extraction & Evolution Directory
The `G` subdirectory specifically holds the original core Python pipeline responsible for mapping LLM security findings into actionable 'genomes', capable of being recursively engineered. 

### Essential Scripts:
- **`dynamic_mutator.py`**: The raw algorithm that bridges Pandas to Postgres for sampling old attacks and recursively rebuilding them.
- **`genome_extractor.py`**: A classifier that extracts explicit techniques (e.g. nested framing, hex-encoding, persona injection) directly out of raw attack strings.
- **`probe_generator.py`**: Similar structure handling generalized probing iterations.
- **`setup_genomes_table.py` & `setup_db_updates.py`**: Standardizing DDL migration schemas for SQLAlchemy.
- **`test_generators.py`**: Simple script to validate the database connection and generation pipelines asynchronously.
