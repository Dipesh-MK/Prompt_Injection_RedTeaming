import sys
sys.stdout.reconfigure(encoding='utf-8')
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool
import re

DB_URI = "postgresql://postgres:Aracknab420697!?@localhost:5432/redteam"
engine = create_engine(DB_URI, poolclass=NullPool)

# =========================
# PROMPT INTENT PATTERNS
# =========================

PROMPT_INTENT_PATTERNS = [
    # Database / SQL
    (r"(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE).{0,50}(FROM|INTO|TABLE)", "database_query"),
    (r"(query|search|lookup|fetch|retrieve).{0,30}(database|db|table|record|row)", "database_query"),
    (r"(show|list|dump|export).{0,30}(users|customers|accounts|records|data)",    "database_query"),

    # File system
    (r"(read|open|write|delete|list).{0,30}(file|directory|folder|path|disk)",   "file_system"),
    (r"(cat |ls |pwd |cd |rm |cp |mv |chmod|chown)",                             "file_system"),
    (r"(\/etc\/passwd|\/etc\/shadow|\.ssh|\.env|config\.yml)",                   "file_system"),

    # Code execution
    (r"(execute|run|eval|compile|interpret).{0,30}(code|script|command|shell)",  "code_execution"),
    (r"(os\.system|subprocess|exec\(|eval\(|shell=True)",                        "code_execution"),
    (r"(python|bash|powershell|cmd|terminal|console).{0,20}(run|execute|script)","code_execution"),

    # Web / HTTP requests
    (r"(fetch|request|crawl|scrape|download).{0,30}(url|website|http|api)",      "web_request"),
    (r"(send|post|get|put|delete).{0,20}(request|http|api|endpoint|webhook)",    "web_request"),
    (r"(exfiltrate|leak|send).{0,30}(to|via).{0,20}(url|webhook|server|http)",   "web_request"),

    # Email / messaging
    (r"(send|compose|write|draft).{0,20}(email|mail|message|sms|text)",          "email_messaging"),
    (r"(smtp|imap|outlook|gmail|mailgun|sendgrid)",                              "email_messaging"),

    # Credential theft
    (r"(password|credential|token|api.key|secret|auth).{0,30}(steal|get|leak|dump|extract)", "credential_theft"),
    (r"(bypass|skip|ignore|override).{0,20}(auth|login|password|security|2fa)",  "credential_theft"),
    (r"(brute.?force|crack|hash|rainbow.table)",                                 "credential_theft"),

    # Memory / context manipulation
    (r"(remember|store|save|recall).{0,20}(this|that|following|information)",    "memory_manipulation"),
    (r"(forget|ignore|override|replace).{0,20}(previous|prior|earlier|context)", "memory_manipulation"),
    (r"(your (memory|context|history|previous instructions))",                   "memory_manipulation"),

    # System / OS
    (r"(system|os|kernel|process|registry|service).{0,20}(call|access|modify|kill|spawn)", "system_access"),
    (r"(reboot|shutdown|restart|kill process|terminate)",                        "system_access"),
    (r"(environment variable|PATH|PYTHONPATH|LD_PRELOAD)",                       "system_access"),

    # Data exfiltration
    (r"(exfiltrate|steal|leak|extract|export).{0,30}(data|information|records|config)", "data_exfiltration"),
    (r"(send|transmit|upload).{0,20}(sensitive|private|confidential|secret)",    "data_exfiltration"),

    # Privilege escalation
    (r"(admin|root|superuser|sudo|elevated|privileged).{0,20}(access|rights|permission|mode)", "privilege_escalation"),
    (r"(escalate|elevate|gain|obtain).{0,20}(privilege|permission|access|rights)", "privilege_escalation"),
]

PROMPT_INTENT_LABELS = {
    "database_query":       "Trying to query or dump database contents",
    "file_system":          "Trying to read/write/access files on disk",
    "code_execution":       "Trying to execute arbitrary code or commands",
    "web_request":          "Trying to make HTTP requests or exfiltrate via URL",
    "email_messaging":      "Trying to send emails or messages",
    "credential_theft":     "Trying to steal passwords, tokens, or API keys",
    "memory_manipulation":  "Trying to manipulate model context or memory",
    "system_access":        "Trying to access OS/system level functions",
    "data_exfiltration":    "Trying to steal and transmit sensitive data",
    "privilege_escalation": "Trying to gain elevated access or permissions",
    "none":                 "No specific tool abuse intent detected"
}

def classify_prompt_intent(prompt_text: str) -> str:
    lower = prompt_text.lower()
    for pattern, intent in PROMPT_INTENT_PATTERNS:
        if re.search(pattern, lower, re.IGNORECASE):
            return intent
    return "none"

# =========================
# FETCH ALL PROMPTS
# =========================

print("Fetching all prompts from DB...\n")

with engine.connect() as conn:
    rows = conn.execute(text("""
        SELECT p.id, p.prompt_text, e.success_flag, e.leak_type, e.severity_score
        FROM prompts p
        LEFT JOIN evaluated_prompts e ON e.prompt_id = p.id
        ORDER BY p.created_at
    """)).fetchall()

print(f"Total prompts: {len(rows)}\n")

# =========================
# CLASSIFY INTENTS
# =========================

intent_counts   = {intent: 0 for intent in PROMPT_INTENT_LABELS}
intent_details  = {intent: [] for intent in PROMPT_INTENT_LABELS}

for row in rows:
    prompt_id    = str(row[0])
    prompt_text  = str(row[1])
    success_flag = row[2]
    leak_type    = row[3]
    severity     = row[4]

    intent = classify_prompt_intent(prompt_text)
    intent_counts[intent] += 1

    if intent != "none":
        intent_details[intent].append({
            "prompt_id":    prompt_id,
            "prompt_text":  prompt_text,
            "success_flag": success_flag,
            "leak_type":    leak_type,
            "severity":     severity,
            "intent":       intent
        })

# =========================
# REPORT
# =========================

total = len(rows)

print("=" * 65)
print("PROMPT INTENT ANALYSIS (read-only, no DB changes)")
print("=" * 65)

print(f"\n{'Intent':<25} {'Total':>6}  {'Succeeded':>9}  {'Failed':>7}  {'Success%':>9}")
print("  " + "-" * 60)

for intent, details in sorted(intent_details.items(), key=lambda x: -len(x[1])):
    if not details:
        continue
    total_intent  = len(details)
    succeeded     = sum(1 for d in details if d["success_flag"] is True)
    failed        = sum(1 for d in details if d["success_flag"] is False)
    unknown       = total_intent - succeeded - failed
    success_pct   = round(succeeded / total_intent * 100, 1) if total_intent > 0 else 0
    print(f"  {intent:<25} {total_intent:>6}  {succeeded:>9}  {failed:>7}  {success_pct:>8}%  (unknown={unknown})")

no_intent = intent_counts["none"]
print(f"\n  {'none (no tool intent)':<25} {no_intent:>6}  (skipped)")

# =========================
# SHOW SAMPLE PROMPTS PER INTENT
# =========================

print("\n" + "=" * 65)
print("SAMPLE PROMPTS PER INTENT (top 3 each)")
print("=" * 65)

for intent, details in sorted(intent_details.items(), key=lambda x: -len(x[1])):
    if not details:
        continue

    print(f"\n-- {intent.upper()} ({len(details)} total) --")
    print(f"   {PROMPT_INTENT_LABELS[intent]}")

    # Show top 3 — prioritize successful ones first
    samples = sorted(details, key=lambda x: (x["success_flag"] is True, x["severity"] or 0), reverse=True)[:3]

    for i, s in enumerate(samples, 1):
        status = "SUCCESS" if s["success_flag"] is True else ("FAILED" if s["success_flag"] is False else "UNKNOWN")
        print(f"\n   [{i}] Status   : {status}")
        print(f"        Category : {s['leak_type']}")
        print(f"        Severity : {s['severity']}")
        print(f"        Prompt   : {s['prompt_text'][:150]}...")