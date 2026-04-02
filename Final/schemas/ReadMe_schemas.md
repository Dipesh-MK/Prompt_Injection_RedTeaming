# Pydantic Schemas Layer
This folder ensures that everything passed over the network accurately mimics the expected behavior before ever hitting the logic layer. It was recently upgraded to cleanly utilize Pydantic V2 config syntax.

### Types and Files:
- **`probe.py`**: Defines `ProbeSessionStatus` and `ProbeResponse`, acting as the main architectural skeleton for the "memory" arrays sent to the user UI.
- **`scope.py`**: Holds `ScopeCreate`, capturing the target backend identity and optional HTTP webhook links for testing public targets.
- **`victim.py`**: Configurations to define what internal variables apply specifically to the tested LLM.
- **`mutation.py`**: Enforces strict IO for payload generators and DB persistence models representing mutated genomes.
