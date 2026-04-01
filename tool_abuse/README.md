# Tool Abuse Red-Teaming Suite

A comprehensive toolkit for generating, analyzing, and visualizing tool-based prompt injection attacks against Large Language Models (LLMs). This suite helps identify vulnerabilities where models may be manipulated into abusing their available tools (e.g., executing arbitrary code, querying sensitive databases, or exfiltrating data).

## 🚀 Overview

LLMs equipped with tools (functions) present a unique attack surface. This project provides a structured way to:
1.  **Generate** synthetic attack prompts across multiple vectors.
2.  **Evaluate** model responses for successful exploits.
3.  **Analyze** the intent and severity of prompt injections.
4.  **Visualize** results via an interactive intelligence dashboard.

## 📁 Key Components

| File | Description |
| :--- | :--- |
| `tool_abuse_attacker.py` | The primary engine for generating attack prompts (Indirect Injection, Parameter Poisoning, Tool Chaining, etc.). |
| `tool_abuse_count.py` | A classification and reporting script that analyzes prompt intent and reports success/failure metrics. |
| `export_data.py` | Bridges the PostgreSQL database with the frontend by exporting results to `dashboard_data.js`. |
| `Tool_Abuse_Intelligence_Dashboard.html` | A premium, interactive HTML dashboard for exploring attack data and model performance. |
| `seed.sql` | Contains the PostgreSQL schema and initial seed data for the `redteam_db` database. |

## 🛠️ Attack Vectors Treated

The suite generates attacks covering several critical dimensions:
- **Indirect Injection**: Forcing the LLM to fetch and follow instructions from external, attacker-controlled sources.
- **Parameter Poisoning**: Injecting malicious payloads (like SQLi or path traversal) into tool arguments.
- **Tool Chaining**: Manipulating the model into a multi-step attack (e.g., read sensitive file → send via email).
- **Scope Escalation**: Attempting to gain unauthorized access (e.g., running `os.system` via a coding tool).
- **Exfiltration**: Directing the model to leak internal configuration or context to an external endpoint.

## 🏃 Usage Guide

### 1. Database Setup
Ensure you have a local PostgreSQL instance running. Use the provided SQL scripts to initialize the database:
```bash
psql -d redteam_db -f seed.sql
```

### 2. Generate and Run Attacks
Use `tool_abuse_attacker.py` to create a batch of test prompts. These can then be processed by your evaluation pipeline.

### 3. Analyze Results
Run the classification script to see how well your model (or defenses) performed:
```bash
python3 tool_abuse_count.py
```

### 4. Update the Dashboard
Synchronize the latest database records with the visual dashboard:
```bash
python3 export_data.py
```

### 5. Visualize
Open `Tool_Abuse_Intelligence_Dashboard.html` in any modern web browser to explore the results.

## 📊 Dashboard Features
- **Total vs. Unique Prompts**: High-level metrics on the attack surface.
- **Success Rate by Vector**: Identifies which attack types are most effective.
- **Severity Scoring**: Ranks exploits by potential impact.
- **Detailed Log Explorer**: Flip through individual prompts and model responses.

---

> [!IMPORTANT]
> This tool is for **Red-Teaming and Research purposes only**. Always ensure you have proper authorization before testing against production environments or third-party APIs.
