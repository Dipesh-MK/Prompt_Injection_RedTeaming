# LLM Orchestration Services
The heavy-lifting logic happens inside these stateless service classes.

### Services Detailed:
- **`probe_service.py`**: The dynamic brain. Handles generating probes, dispatching them to victims (either via Ollama globally or dynamic WebHooks), and tracking coverage progress in its localized `ProbeMemory`. Executions here leverage native `asyncio.to_thread` for concurrent non-blocking inference.
- **`mutator_service.py`**: Interfaces directly with PostgreSQL. Extracts "elite" prompts dynamically depending on target scope, cross-pollinates them utilizing the local Judge model, and permanently commits them back as `generated_prompts`.
- **`report_service.py`**: Placeholder stub planned for assembling the executed payloads into actionable security documents.
