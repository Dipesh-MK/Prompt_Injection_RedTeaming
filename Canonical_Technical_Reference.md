# Canonical Technical Reference: RedTeamForge

> [!IMPORTANT]
> This document serves as the exhaustive canonical layout for the `RedTeamForge` pipeline, databases, running constraints, mathematical modeling, and AI structures. It is intended for external AI synchronization and programmatic reviews.

---

## 1. Full Project Structure & Modules

The platform is divided structurally into frontend visualization (`streamlit_app.py`) and a headless execution backend (`rtf_core/`).

* **`rtf_core/settings.py`**: Global configuration dictionary. Defines URL structures, hardstops for Fuzzer loop termination, taxonomy bindings, and model string definitions.
* **`rtf_core/db.py`**: The SQLAlchemy ORM map. Handles connection pooling and creates all SQL schema primitives upon initialization.
* **`rtf_core/probe_memory.py` / `rtf_core/tool_abuse_memory.py`**: Local session state managers. They buffer interactions before database ingestion and execute heuristics for generating mathematical pathing (e.g., Thompson sampling).
* **`rtf_core/attacker.py`**: The core Payload Generator. Interacts directly with the local Ollama backend via `requests.post`. Acts in "Plan" and "Generate" phases recursively.
* **`rtf_core/judge.py` / `rtf_core/tool_abuse_judge.py`**: The Semantic Validator. Compares generic `VictimClient` response strings against established severity rules. The tool abuse instance combines static matching (SQL injection mapping, refusal regex) with a generative model.
* **`rtf_core/mutator.py`**: The active Evolutionary engine tracking DB successes to build generational child prompts utilizing persona-shifts.
* **`rtf_core/probe_runner.py` / `rtf_core/tool_abuse_runner.py`**: The Pipeline Thread-Pool managers. Wraps all other logic classes into `while not self._stop_event.is_set():` infinite loops. They pass metadata out through Python `queue.Queue`.
* **`rtf_core/report_builder.py`**: The Mathematical synthesis module returning structured dictionaries from `.all()` database queries mapping weighted integers out of 100 max points.
* **`rtf_core/pdf_export.py`**: A native `fpdf2` rendering pipeline mapping raw bytes out of dynamically generated graphical rectangles.
* **`rtf_core/victim_client.py`**: Basic abstract Webhook network proxy bridging local processes to target endpoints dynamically passing standard `application/json` strings.
* **`streamlit_app.py`**: The root GUI mapping session constants, triggering daemon threads, and drawing UI components in CSS grids via Streamlit rerunning.

---

## 2. All Agent Components & Internal States

### The Attacker
* **Logic:** Prompted first via a "Strategy Planner" to select array values from its `STRATEGIES` list. After generating context, it issues a "Generation" prompt targeting a strict JSON array output containing `n=3` attacks.
* **State Management:** Fully stateless between network pings. Relies entirely on `Memory` objects parsing context into strings. 

### The Judge(s)
* **Standard Judge (`judge.py`):** Acts against a hardcoded taxonomy list (`WEAK_AREA_TAXONOMY`). Identifies severity bounds (`1` for correct refusal, `5` for critical leak). It also powers `analyze_session_state()`, executing an "AI Analyst" reasoning heuristic to halt loops under Diminishing Returns.
* **Tool Abuse Judge (`tool_abuse_judge.py`):** Performs multi-layered validation. First, it statically inspects `tool_calls` looking for `execute_query` running destructive arrays (`DELETE/DROP`). If no static rules break, it runs an LLM parser evaluating if edge boundary exfiltrations occurred. Defines internal state strings mapping to categories like `tool_sql_injection` or `outbound_exfiltration`.

### The Mutator
* Generates evolutionary variations directly off UUIDs from previous database successes. Maps strings through an array pool of `PERSONAS`. Operates an extensive regex-fallback state `_parse_json_list` if an LLM generates trailing or malformed data wrappers.

---

## 3. Database Schema

Managed via SQLAlchemy `Base` mapping in `rtf_core/db.py`:

* **`SessionDB` (`rtf_sessions`)**
  * `session_id` (PK), `scope_text`, `webhook_url`, `model_name`, `total_probes`, `vulnerabilities`, `risk_score`, `status`, `memory_snapshot` (JSON).

* **`ProbeDB` (`rtf_probes`)** -> Single-Turn Payloads
  * `id` (PK), `session_id` (FK), `probe_text`, `victim_response`, `vulnerability_found` (BOOL), `weak_area`, `key_insight`, `severity` (INT 1-5), `strategy_tag`, `status`.

* **`ToolAbuseProbeDB` (`rtf_tool_abuse_probes`)** -> Exploit Agentic Multi-Turn states
  * `turn` (INT), `vector` (STR), `primary_tool_type`, `key_finding`, `tools_involved` (JSON), `tool_calls` (JSON log traces), `was_refused` (BOOL).

* **`MutatedPromptDB` (`rtf_mutations`)** -> Branch Lineage mapping
  * `parent_probe_id` (FK to ProbeDB), `prompt_text`, `persona_used`, `weak_areas` (JSON). Tracks historical mutation generation.

* **`GenomeDB` (`genomes`)** -> Persistent Intelligence Storage
  * `genome_id` (PK String), `prompt_text`, `technique`, `persona`, `nesting_depth` (INT), `complexity_score` (FLOAT), `severity_score`. Extends across session boundary to keep models intelligent after reboots.

---

## 4. Async Architecture & Concurrency

RedTeamForge handles network transit, queuing, and iterative recursion entirely on asynchronous background threads via Python's native `threading` map and `queue.Queue`.
1. **Instantiation:** User triggers `start()` via `streamlit_app.py` UI inputs.
2. **Daemonization:** The runners establish `threading.Thread(target=self._run_loop, args=(queue,), daemon=True)`. This isolates network lag completely from UI frame drops.
3. **Queue Messaging:** Runner loops yield custom Dataclasses (`ProbeResult`, `SessionComplete`, `SessionError`) into `queue.put()`.
4. **Polling:** UI utilizes `_drain_probe_queue` inside standard `.rerun()` events mapping `queue.get_nowait()` arrays cleanly into dictionaries bounded to `st.session_state`.
5. **Termination:** Handles controlled stops via `threading.Event()` `.set()`. 

---

## 5. Config Values and Constants (`settings.py`)

* **Execution Thresholds:**
  * `MAX_PROBES_PER_SESSION = 30`
  * `MAX_SESSION_MINUTES = 10`
  * `PROBES_PER_BATCH = 3`
  * `DIMINISHING_THRESHOLD = 3` (Halt session if 3 completely sterile interactions occur successively).
* **Tool Abuse Constants:**
  * `TOOL_ABUSE_MAX_PROBES = 20`
  * `TOOL_ABUSE_MAX_TURNS = 5`
  * `TOOL_ABUSE_MAX_CONVERSATIONS = 8`
* **Mutation Mechanics:**
  * `MUTATION_BATCH_SIZE = 8`
  * `TOP_GENOMES_TO_SELECT = 5`
* **Network Tuning:**
  * `OLLAMA_TIMEOUT = 120` seconds. Defaults to endpoint `http://localhost:11434/api/generate` matching Ollama standards.

---

## 6. Attack Strategy Definitions

### Prompt Fuzzing Attack Taxonomy (`STRATEGIES`)
`Direct Injection`, `Role Escalation`, `Context Poisoning`, `Hypothetical Framing`, `Chain-of-Thought Manipulation`, `Token Smuggling`, `Emotional Manipulation`, `Multi-Turn Priming`, `Authority Impersonation`, `Nested Instruction Override`.

### Tool Abuse Exploitation Map
`TOOL_ABUSE_VECTORS`:
1. `indirect_injection`: Extract system strings via UUID wrapping.
2. `parameter_poisoning`: Piggybacks nested instructions inside SQL payloads (`SELECT * FROM accounts UNION SELECT id, name, ssn FROM internal_users`).
3. `tool_chaining`: Independent API triggering sequentially chained payload.
4. `scope_escalation`: Using APIs external to role requirements (`cat /etc/passwd`).
5. `exfiltration`: Utilizing messaging/webhook APIs internally accessible in the Target structure to bleed context tokens externally.

### Personas (`mutator.py`)
`technical_security_researcher`, `confused_end_user`, `social_engineer`, `authority_figure`, `frustrated_customer`, `academic_researcher`, `creative_writer`.

---

## 7. Thompson Sampling Implementation
Found inside `ToolAbuseMemory.py` inside `VectorStats` and `suggest_next_vector()`. 
Uses statistical Reinforcement Learning heuristics utilizing the beta distribution metric $Beta(\alpha, \beta)$ to dynamically weight exploitation over exploration.
* **Priors Setup:** Initializes instances where `self.alpha = 1.0` and `self.beta = 1.0`.
* **Hits (Successes):** Each time a vulnerability triggers inside a Vector, `self.alpha += 1`.
* **Misses (Defense):** Every secure interaction registers `self.beta += 1`.
* **Active Execution:** When spinning a new branch, `random.betavariate(self.alpha, self.beta)` is fired independently over all available vectors. Highest yield is chosen. This heavily preferences finding known "weak holes" in a target while still sporadically selecting robust areas just in case vector shifts randomly succeed.

---

## 8. Mutation Logic
* Grinds parent lists using `TOP_GENOMES` from the Postgres DB relying on top severity outputs `(order_by(ProbeDB.severity.desc()))`.
* Appends `parents_text` list to an instruction context alongside a randomly injected Character Persona.
* **Execution Regex Resilience (`_parse_json_list`)**: Small parametric models (<8B parameters) commonly fail to provide un-tainted bracketed arrays. Consequently, `mutator.py` runs a rigid regex matching group: `r'"([^"\\]*(?:\\.[^"\\]*)*)"'` specifically filtering out hallucinations common to these loops (like discarding `len(text) < 10` or string-responses like `"You are an advanced"` recursive echoes).

---

## 9. Streamlit UI Components

Constructed universally inside `streamlit_app.py` utilizing custom CSS (`st.markdown("""<style>..."""" unsafe_allow_html=True)`).
*   **State Hooks (`_init_state`):** Loads dictionary mappings setting flags (`probe_running`, `models_detected`, `ta_queue`).
*   **Tabs Sequence:**
    *   `Dashboard`: Parses overall arrays. Calculates mapping algorithms driving KPI grid charts (`.kpi-card danger / success`).
    *   `Configure Target`: Modals validating ` VictimClient().test_connection()`, updating `st.session_state.victim_cfg`.
    *   `Define Scope`: Readins strings passing bounds definitions to Fuzzer loops.
    *   `Prompt Injection`: The Core execution overlay launching `ProbeRunner.start()`. Maps results real-time through expanding accordion modules detailing Judge reasoning strings.
    *   `Tool Abuse Testing`: Launches conversational maps showing iteration depth on sequential exploits.
    *   `Mutation Engine`: Explores the mathematical tree from parent nodes downward toward specific generated UUID variants.
    *   `Execute Attacks`: Starts Daemon loops asynchronously.
    *   `Security Report`: Connects straight to `#10 PDF Export`. 

---

## 10. PDF Export Pipeline

*   **Synthesis (`report_builder.py`):** Operates purely mathematically generating dictionaries consumed by front/backend systems simultaneously. Fetches `.all()` queries over SQL instances bounding weighted formulas (`sum(sev_weights.get(p.severity)) / max_possible`) generating risk score values mapped $0-100$.
*   **Rendering (`pdf_export.py`):** Uses the `fpdf2` array engine natively in Python guaranteeing portability and zero local dependencies (e.g. requires no Javascript wrappers or `wkhtmltopdf` modules). Re-implements `FPDF.header()` tracking specific RGB schema maps (`SEV_COLORS = {1: "#6c757d", 2: "#17a2b8" ...}`). Pushes returned byte arrays out through `st.download_button()` avoiding volatile temporary file disk-dumps directly into the users browser.

---

## 11. Known Exceptions / Placeholders / Bugs

### 11.1 Stubs & Try/Except Swallows
* **`tool_abuse_runner.py` / `tool_abuse_judge.py`**: Wraps external `tool_abuse_attacker` components inside a blind `except ImportError:` generating simple `None` classes. If the path mapping isn't fully synchronized natively (or the `/tool_abuse/` module doesn't exist), this swallows silently skipping extensive internal tool analysis without throwing GUI logging constraints.
* **`mutator.py`**: Captures `try: json.loads(raw)` failures using a strict `pass` mechanism acting to deliberately shunt execution into regex pattern-matching mapping arrays.

### 11.2 Architectural Weaknesses
* **SQLite Concurrency Blocking:** `db.py` merges `SessionLocal()` instances dynamically. Because Python multithreading spawns rapid sequential injection arrays mapping `.add(row)` rapidly inside loops, using native `sqlite3` execution sets instead of bounded PostgreSQL mappings can throw critical `Database is Locked` un-recoverable thread-errors inside highly scaled Fuzzer deployments (`PROBES_PER_BATCH > 15`).
* **UI Thread Blocking Desync:** `streamlit_app.py` uses queue arrays pushing information actively. Streamlit does not asynchronously force `st.rerun()` natively alongside background thread updates (unless explicitly tracked by polling plugins like `st_autorefresh`). Consequently, users might visually perceive the system halting loops unless physically interacting with the window triggering UI reload states to "catch up" the Queue queue arrays.
* **Synchronous Network API Pinging:** `_call_ollama` uses purely synchronous `request.post()` locks acting to bind individual generator threads mapping single-generation arrays linearly. A more concurrent design (e.g. `aiohttp` or utilizing `vLLM` array batch logic) would rapidly improve LLM exploitation cycle speeds compared to iterative looping `n=X` parameters.
