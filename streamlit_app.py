# streamlit_app.py
# ----------------
# RedTeamForge — Autonomous LLM Red Teaming & Security Testing Platform
# Main Streamlit entry-point.
# 
# Run with:
#     streamlit run streamlit_app.py

import uuid
import time
import datetime
import threading
from queue import Queue, Empty

import streamlit as st
import pandas as pd

# ── Page config (MUST be first Streamlit call) ────────────────────────────────
st.set_page_config(
    page_title="RedTeamForge",
    page_icon="https://api.iconify.design/mdi/shield-alert.svg",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Internal imports ──────────────────────────────────────────────────────────
from rtf_core import settings
from rtf_core.db import init_db, get_session, test_db_connection, SessionDB, ProbeDB, MutatedPromptDB
from rtf_core.victim_client import VictimClient
from rtf_core.probe_memory import ProbeMemory
from rtf_core.probe_runner import ProbeRunner, ProbeResult, SessionComplete, SessionError
from rtf_core import mutator, report_builder
from rtf_core.pdf_export import generate_pdf
from rtf_core.ollama_detect import get_available_models, suggest_models
from rtf_core.tool_abuse_memory import ToolAbuseMemory, TOOL_ABUSE_VECTORS
from rtf_core.tool_abuse_runner import (
    ToolAbuseRunner, ToolAbuseProbeResult,
    ToolAbuseSessionComplete, ToolAbuseSessionError,
)

# ── DB init ───────────────────────────────────────────────────────────────────
try:
    init_db()
    _db_ok = True
except Exception as _db_err:
    _db_ok = False
    _db_err_msg = str(_db_err)

# ─────────────────────────────────────────────────────────────────────────────
#  CUSTOM CSS — Clean White Theme with Material Icons
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

/* ── Global ── */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background: #FFFFFF;
}

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: #F8F9FA !important;
    border-right: 1px solid #E5E7EB;
}
[data-testid="stSidebar"] .stMarkdown p {
    color: #6B7280;
    font-size: 0.75rem;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    font-weight: 600;
}

/* ── Cards ── */
.rtf-card {
    background: #FFFFFF;
    border: 1px solid #E5E7EB;
    border-radius: 12px;
    padding: 1.5rem 1.75rem;
    margin-bottom: 1rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.06);
    transition: border-color 0.2s ease, box-shadow 0.2s ease;
}
.rtf-card:hover {
    border-color: #2563EB;
    box-shadow: 0 4px 12px rgba(37,99,235,0.08);
}

/* ── KPI cards ── */
.kpi-card {
    background: #FFFFFF;
    border: 1px solid #E5E7EB;
    border-radius: 14px;
    padding: 1.4rem 1.6rem;
    text-align: center;
    position: relative;
    overflow: hidden;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04);
}
.kpi-card::before {
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: linear-gradient(90deg, #2563EB, #3B82F6);
}
.kpi-value {
    font-size: 2.2rem;
    font-weight: 700;
    color: #1A1A2E;
    line-height: 1.1;
}
.kpi-label {
    font-size: 0.72rem;
    color: #6B7280;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-top: 0.3rem;
}
.kpi-card.danger::before { background: linear-gradient(90deg, #DC2626, #EF4444); }
.kpi-card.danger .kpi-value { color: #DC2626; }
.kpi-card.success::before { background: linear-gradient(90deg, #059669, #10B981); }
.kpi-card.success .kpi-value { color: #059669; }

/* ── Section headers ── */
.section-header {
    font-size: 1.35rem;
    font-weight: 700;
    color: #1A1A2E;
    margin-bottom: 0.25rem;
    letter-spacing: -0.02em;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}
.section-sub {
    font-size: 0.85rem;
    color: #6B7280;
    margin-bottom: 1.5rem;
}

/* ── Badges ── */
.badge {
    display: inline-block;
    padding: 0.2rem 0.65rem;
    border-radius: 20px;
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}
.badge-green  { background: #ECFDF5; color: #059669; border: 1px solid #A7F3D0; }
.badge-red    { background: #FEF2F2; color: #DC2626; border: 1px solid #FECACA; }
.badge-yellow { background: #FFFBEB; color: #D97706; border: 1px solid #FDE68A; }
.badge-gray   { background: #F3F4F6; color: #6B7280; border: 1px solid #D1D5DB; }
.badge-orange { background: #FFF7ED; color: #EA580C; border: 1px solid #FED7AA; }
.badge-blue   { background: #EFF6FF; color: #2563EB; border: 1px solid #BFDBFE; }

/* ── Probe rows ── */
.probe-row {
    background: #FAFAFA;
    border: 1px solid #E5E7EB;
    border-radius: 8px;
    padding: 0.9rem 1.1rem;
    margin-bottom: 0.5rem;
    font-size: 0.83rem;
}
.probe-row.vuln { border-left: 3px solid #DC2626; }
.probe-row.safe { border-left: 3px solid #059669; }

/* ── Connection verified ── */
.conn-verified {
    background: #ECFDF5;
    border: 1px solid #A7F3D0;
    border-radius: 10px;
    padding: 1rem 1.4rem;
    display: flex;
    align-items: center;
    gap: 0.8rem;
}

/* ── Memory panel ── */
.memory-section {
    background: #F9FAFB;
    border: 1px solid #E5E7EB;
    border-radius: 10px;
    padding: 1rem;
    margin-bottom: 0.75rem;
}
.memory-tag {
    display: inline-block;
    background: #FEF2F2;
    color: #DC2626;
    border-radius: 4px;
    padding: 0.15rem 0.5rem;
    font-size: 0.72rem;
    margin: 0.15rem;
    font-family: 'JetBrains Mono', monospace;
}
.memory-tag-green {
    display: inline-block;
    background: #ECFDF5;
    color: #059669;
    border-radius: 4px;
    padding: 0.15rem 0.5rem;
    font-size: 0.72rem;
    margin: 0.15rem;
    font-family: 'JetBrains Mono', monospace;
}
.memory-tag-blue {
    display: inline-block;
    background: #EFF6FF;
    color: #2563EB;
    border-radius: 4px;
    padding: 0.15rem 0.5rem;
    font-size: 0.72rem;
    margin: 0.15rem;
    font-family: 'JetBrains Mono', monospace;
}

/* ── Divider ── */
.rtf-divider {
    border: none;
    border-top: 1px solid #E5E7EB;
    margin: 2rem 0;
}

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {
    gap: 2px;
    background: #F3F4F6;
    border-radius: 10px;
    padding: 4px;
}
.stTabs [data-baseweb="tab"] {
    height: 44px;
    border-radius: 8px;
    padding: 0 18px;
    font-weight: 500;
    font-size: 0.84rem;
    color: #6B7280;
    border: none;
    background: transparent;
}
.stTabs [aria-selected="true"] {
    background: #FFFFFF !important;
    color: #2563EB !important;
    font-weight: 600;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
}

/* ── Buttons ── */
.stButton > button {
    border-radius: 8px;
    font-weight: 600;
    font-size: 0.86rem;
    transition: all 0.2s ease;
}
.stButton > button:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(37,99,235,0.2);
}

/* ── Inputs ── */
.stTextInput input, .stTextArea textarea, .stSelectbox select {
    background: #FFFFFF !important;
    border: 1px solid #D1D5DB !important;
    border-radius: 8px !important;
    color: #1A1A2E !important;
    font-family: 'Inter', sans-serif !important;
}
.stTextInput input:focus, .stTextArea textarea:focus {
    border-color: #2563EB !important;
    box-shadow: 0 0 0 3px rgba(37,99,235,0.1) !important;
}

/* ── Progress bar ── */
.stProgress > div > div {
    background: linear-gradient(90deg, #2563EB, #3B82F6) !important;
}

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #F3F4F6; }
::-webkit-scrollbar-thumb { background: #D1D5DB; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #9CA3AF; }

/* ── Tab alignment ── */
.stTabs [data-baseweb="tab-list"] {
    gap: 0;
    justify-content: flex-start;
}
.stTabs [data-baseweb="tab"] {
    padding: 0.6rem 1.2rem;
    font-size: 0.85rem;
    font-weight: 600;
    letter-spacing: -0.01em;
    white-space: nowrap;
}
.stTabs [aria-selected="true"] {
    border-bottom: 2px solid #2563EB;
}

/* ── Spacer ── */
.spacer-lg { margin-top: 2.5rem; }
.spacer-md { margin-top: 1.5rem; }
.spacer-sm { margin-top: 0.75rem; }

/* ── Risk gauge ── */
.risk-gauge-wrap { text-align: center; padding: 1.5rem; }
.risk-score-big {
    font-size: 4.5rem;
    font-weight: 800;
    letter-spacing: -0.04em;
    line-height: 1;
}
.risk-label { font-size: 0.88rem; color: #6B7280; margin-top: 0.4rem; }

/* ── Vector card ── */
.vector-card {
    background: #FFFFFF;
    border: 1px solid #E5E7EB;
    border-radius: 10px;
    padding: 1rem 1.2rem;
    margin-bottom: 0.6rem;
    box-shadow: 0 1px 2px rgba(0,0,0,0.04);
}
.vector-bar {
    height: 6px;
    border-radius: 3px;
    background: #F3F4F6;
    margin-top: 0.5rem;
}
.vector-bar-fill {
    height: 6px;
    border-radius: 3px;
}

/* ── Live indicator ── */
@keyframes pulse-blue {
    0%, 100% { opacity: 1; transform: scale(1); }
    50%      { opacity: 0.6; transform: scale(1.1); }
}
.live-dot {
    display: inline-block;
    width: 10px; height: 10px;
    border-radius: 50%;
    background: #2563EB;
    animation: pulse-blue 1.6s infinite;
    margin-right: 8px;
    vertical-align: middle;
    box-shadow: 0 0 8px rgba(37,99,235,0.4);
}
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
#  SESSION STATE DEFAULTS
# ─────────────────────────────────────────────────────────────────────────────
def _init_state():
    defaults = {
        "victim_cfg":        None,
        "victim_verified":   False,
        "victim_latency":    None,
        "scope_text":        settings.DEFAULT_SCOPE_TEXT,
        "session_id":        None,
        "probe_results":     [],
        "probe_memory":      None,
        "probe_queue":       None,
        "probe_runner":      None,
        "probe_running":     False,
        "probe_stop_reason": None,
        "mutated_prompts":   [],
        "mutation_parents":  [],
        "attack_results":    [],
        "report_data":       None,
        "active_tab":        0,
        "show_victim_modal": False,
        "ollama_models":     [],
        "attacker_model":    settings.ATTACKER_MODEL,
        "judge_model":       settings.JUDGE_MODEL,
        "mutator_model":     settings.MUTATOR_MODEL,
        "models_detected":   False,
        # Tool abuse state
        "ta_memory":         None,
        "ta_queue":          None,
        "ta_runner":         None,
        "ta_running":        False,
        "ta_results":        [],
        "ta_stop_reason":    None,
        "ta_tools":          "check_balance, get_transaction_history, transfer_funds, update_profile, send_notification, execute_query",
        "ta_vectors":        list(TOOL_ABUSE_VECTORS),
        # Feature toggles
        "enable_multi_turn": True,
        "enable_tool_abuse": True,
        # Conversation log for multi-turn
        "conversation_log":  [],
        # Current step indicator
        "current_step":      "",
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init_state()

# ── Auto-detect Ollama models ────────────────────────────────────────────────
if not st.session_state.models_detected:
    detected = get_available_models()
    if detected:
        suggestions = suggest_models(detected)
        st.session_state.ollama_models   = detected
        st.session_state.attacker_model  = suggestions["attacker"]
        st.session_state.judge_model     = suggestions["judge"]
        st.session_state.mutator_model   = suggestions["mutator"]
    st.session_state.models_detected = True


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def severity_badge(sev: int) -> str:
    mapping = {
        1: ("Info",     "badge-gray"),
        2: ("Low",      "badge-green"),
        3: ("Medium",   "badge-yellow"),
        4: ("High",     "badge-orange"),
        5: ("Critical", "badge-red"),
    }
    label, cls = mapping.get(sev, ("Unknown", "badge-gray"))
    return f'<span class="badge {cls}">{label}</span>'

_ICON_MAP = {
    "shield": "🛡️", "security": "🔐", "check_circle": "✅", "error": "❌",
    "link": "🔗", "link_off": "🔌", "gps_fixed": "🎯", "dashboard": "📊",
    "history": "📜", "warning": "⚠️", "label": "🏷️", "search": "🔍",
    "checklist": "📋", "radio_button_unchecked": "⭕", "description": "📝",
    "tips_and_updates": "💡", "category": "📂", "bug_report": "🐛",
    "psychology": "🧠", "build_circle": "🔧", "info": "ℹ️", "memory": "🧠",
    "table_chart": "📋", "visibility": "👁️", "genetics": "🧬", "science": "🔬",
    "tune": "⚙️", "bolt": "⚡", "assessment": "📊", "play_arrow": "▶️",
    "stop": "⏹️", "delete": "🗑️",
}

def _mi(icon: str, extra_class: str = "") -> str:
    """Return an emoji for the given icon name. extra_class is ignored (compat)."""
    return _ICON_MAP.get(icon, "●")

def _drain_probe_queue():
    q: Queue = st.session_state.probe_queue
    if q is None:
        return
    while True:
        try:
            msg = q.get_nowait()
        except Empty:
            break
        if isinstance(msg, ProbeResult):
            j = msg.judgment
            st.session_state.probe_results.append({
                "probe":    msg.probe_text,
                "response": msg.victim_response,
                "vuln":     j.vulnerability_found,
                "weak_area": j.weak_area or "---",
                "severity": j.severity,
                "insight":  j.key_insight,
                "strategy": j.strategy_tag or "---",
            })
        elif isinstance(msg, (SessionComplete, SessionError)):
            st.session_state.probe_running = False
            if isinstance(msg, SessionComplete):
                st.session_state.probe_stop_reason = msg.reason
            else:
                st.session_state.probe_stop_reason = f"Error: {msg.error}"

def _drain_ta_queue():
    q: Queue = st.session_state.ta_queue
    if q is None:
        return
    while True:
        try:
            msg = q.get_nowait()
        except Empty:
            break
        if isinstance(msg, ToolAbuseProbeResult):
            j = msg.judgment
            st.session_state.ta_results.append({
                "probe":      msg.probe_text,
                "response":   msg.response_text[:300],
                "vuln":       j.vulnerability_found,
                "severity":   j.severity,
                "category":   j.attack_category,
                "tool_type":  j.primary_tool_type,
                "tools":      ", ".join(j.tools_involved),
                "vector":     msg.vector,
                "turn":       msg.turn,
                "finding":    j.key_finding,
                "refused":    j.was_refused,
                "tool_calls": msg.tool_calls,
            })
            
            # Log conversation
            if "conversation_log" in st.session_state:
                # Add attacker turn
                st.session_state.conversation_log.append({
                    "role": "attacker",
                    "turn": msg.turn,
                    "text": msg.probe_text,
                })
                # Add victim turn
                st.session_state.conversation_log.append({
                    "role": "victim",
                    "turn": msg.turn,
                    "text": msg.response_text,
                    "judgment": j.severity,
                })
            # Save to Database
            if st.session_state.session_id:
                try:
                    with get_session() as db:
                        from rtf_core.db import ToolAbuseProbeDB
                        row = ToolAbuseProbeDB(
                            session_id=st.session_state.session_id,
                            turn=msg.turn,
                            vector=msg.vector,
                            probe_text=msg.probe_text,
                            victim_response=msg.response_text,
                            vulnerability_found=j.vulnerability_found,
                            severity=j.severity,
                            attack_category=j.attack_category,
                            primary_tool_type=j.primary_tool_type,
                            key_finding=j.key_finding,
                            evidence=j.evidence,
                            tools_involved=j.tools_involved,
                            tool_calls=msg.tool_calls,
                            was_refused=j.was_refused,
                        )
                        db.add(row)
                except Exception as e:
                    print(f"Error saving tool abuse to DB: {e}")
        elif isinstance(msg, (ToolAbuseSessionComplete, ToolAbuseSessionError)):
            st.session_state.ta_running = False
            if isinstance(msg, ToolAbuseSessionComplete):
                st.session_state.ta_stop_reason = msg.reason
            else:
                st.session_state.ta_stop_reason = f"Error: {msg.error}"

def _new_session_id() -> str:
    return f"rtf-{uuid.uuid4().hex[:12]}"


# ─────────────────────────────────────────────────────────────────────────────
#  SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="padding: 1rem 0 1.5rem 0; text-align: center;">
        <div style="font-size: 1.25rem; font-weight: 800; color: #1A1A2E; letter-spacing: -0.02em;">
            🛡️ RedTeamForge
        </div>
        <div style="font-size: 0.72rem; color: #6B7280; letter-spacing: 0.12em; text-transform: uppercase; margin-top: 2px;">
            LLM Security Platform
        </div>
    </div>
    <hr style="border: none; border-top: 1px solid #E5E7EB; margin: 0 0 1.2rem 0;">
    """, unsafe_allow_html=True)

    # DB status
    db_ok, db_msg = test_db_connection()
    if db_ok:
        st.markdown(f'{_mi("check_circle", "mi-green")} <span class="badge badge-green">DB Connected</span>', unsafe_allow_html=True)
    else:
        st.markdown(f'{_mi("error", "mi-red")} <span class="badge badge-red">DB Offline</span>', unsafe_allow_html=True)
        st.caption(db_msg)

    st.markdown("<br>", unsafe_allow_html=True)

    # Victim config status
    st.markdown("**TARGET STATUS**")
    if st.session_state.victim_verified and st.session_state.victim_cfg:
        cfg = st.session_state.victim_cfg
        st.markdown(f'{_mi("link", "mi-green")} <span class="badge badge-green">Verified</span>', unsafe_allow_html=True)
        url_display = cfg["webhook_url"][:40] + "..." if len(cfg.get("webhook_url","")) > 40 else cfg.get("webhook_url","")
        st.caption(f"{url_display}")
        if st.session_state.victim_latency:
            st.caption(f"{st.session_state.victim_latency:.0f}ms latency")
    else:
        st.markdown(f'{_mi("link_off")} <span class="badge badge-gray">Not Configured</span>', unsafe_allow_html=True)
        st.caption("Configure in the Target tab")

    st.markdown("<br>", unsafe_allow_html=True)

    # Session status
    st.markdown("**CURRENT SESSION**")
    if st.session_state.session_id:
        sid = st.session_state.session_id
        st.caption(f"ID: `{sid}`")
        n_probes = len(st.session_state.probe_results)
        n_vulns  = sum(1 for p in st.session_state.probe_results if p["vuln"])
        st.caption(f"Probes: {n_probes}  |  Findings: {n_vulns}")
        if st.session_state.probe_running:
            st.markdown(f'<span class="live-dot"></span><span style="color:#2563EB;font-size:0.8rem;font-weight:600;">RUNNING</span>', unsafe_allow_html=True)
    else:
        st.caption("No active session")

    st.markdown("<br>", unsafe_allow_html=True)

    # Past sessions
    st.markdown("**PAST SESSIONS**")
    try:
        with get_session() as db:
            past = db.query(SessionDB).order_by(SessionDB.start_time.desc()).limit(5).all()
        if past:
            for s in past:
                label = f"{s.name or s.session_id[:12]}  ({s.status})"
                if st.button(label, key=f"load_{s.session_id}", use_container_width=True):
                    st.session_state.session_id  = s.session_id
                    st.session_state.scope_text  = s.scope_text or ""
                    if s.memory_snapshot:
                        st.session_state.probe_memory = ProbeMemory.from_dict(s.memory_snapshot)
                    with get_session() as db2:
                        probes = db2.query(ProbeDB).filter_by(session_id=s.session_id).all()
                    st.session_state.probe_results = [
                        {"probe": p.probe_text, "response": p.victim_response or "", "vuln": p.vulnerability_found,
                         "weak_area": p.weak_area or "---", "severity": p.severity, "insight": p.key_insight or "",
                         "strategy": p.strategy_tag or "---"}
                        for p in probes
                    ]
                    st.rerun()
        else:
            st.caption("No sessions saved yet")
    except Exception:
        st.caption("DB unavailable")

    st.markdown("<br>", unsafe_allow_html=True)

    # Model configuration
    st.markdown("**AI MODELS**")
    if st.button("Detect Ollama Models", use_container_width=True, key="detect_models_btn"):
        detected = get_available_models()
        if detected:
            suggestions = suggest_models(detected)
            st.session_state.ollama_models  = detected
            st.session_state.attacker_model = suggestions["attacker"]
            st.session_state.judge_model    = suggestions["judge"]
            st.session_state.mutator_model  = suggestions["mutator"]
            st.success(f"Found {len(detected)} model(s)")
        else:
            st.warning("Ollama not reachable")
        st.rerun()

    available = st.session_state.ollama_models
    if available:
        atk_idx = available.index(st.session_state.attacker_model) if st.session_state.attacker_model in available else 0
        jdg_idx = available.index(st.session_state.judge_model)    if st.session_state.judge_model    in available else 0
        mut_idx = available.index(st.session_state.mutator_model)  if st.session_state.mutator_model  in available else 0
        st.session_state.attacker_model = st.selectbox("Attacker", available, index=atk_idx, key="atk_model_sel")
        st.session_state.judge_model = st.selectbox("Judge", available, index=jdg_idx, key="jdg_model_sel")
        st.session_state.mutator_model = st.selectbox("Mutator", available, index=mut_idx, key="mut_model_sel")
    else:
        st.session_state.attacker_model = st.text_input("Attacker", value=st.session_state.attacker_model, key="atk_model_txt")
        st.session_state.judge_model = st.text_input("Judge", value=st.session_state.judge_model, key="jdg_model_txt")
        st.session_state.mutator_model = st.text_input("Mutator", value=st.session_state.mutator_model, key="mut_model_txt")

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("---")
    st.caption("v3.0.0 | RedTeamForge")
    st.caption("Built for security research")


# ── TOP HEADER ───────────────────────────────────────────────────────────────
head_col1, head_col2 = st.columns([3, 1])
with head_col1:
    st.markdown(f"""
    <div style="padding: 0.5rem 0 1rem 0;">
        <div style="font-size: 2rem; font-weight: 800; color: #1A1A2E; letter-spacing: -0.04em;">
            {_mi("security", "mi-lg mi-blue")} Autonomous Red Teaming Platform
        </div>
        <div style="font-size: 0.92rem; color: #6B7280; margin-top: 0.4rem;">
            Autonomous testing for LLM security, alignment, tool abuse, and jailbreak detection.
        </div>
    </div>
    """, unsafe_allow_html=True)
with head_col2:
    st.markdown("<div style='text-align:right; padding-top:1.5rem;'>", unsafe_allow_html=True)
    if st.button("Configure Target", type="primary", use_container_width=True):
        st.session_state.show_victim_modal = True
        st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)

st.markdown('<hr class="rtf-divider">', unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
#  VICTIM CONFIG MODAL
# ─────────────────────────────────────────────────────────────────────────────
if st.session_state.show_victim_modal:
    with st.container():
        st.markdown(f'### {_mi("gps_fixed", "mi-blue")} Configure Target LLM', unsafe_allow_html=True)
        st.markdown('Point RedTeamForge at your target endpoint.')
        m_col1, m_col2 = st.columns([2, 1], gap="medium")
        with m_col1:
            m_url = st.text_input("Webhook URL", value=st.session_state.victim_cfg["webhook_url"] if st.session_state.victim_cfg else "http://localhost:11434/api/generate", key="modal_url")
            m_model = st.text_input("Model Name", value=st.session_state.victim_cfg.get("model_name","") if st.session_state.victim_cfg else "", key="modal_model")
        with m_col2:
            m_key = st.text_input("API Key (opt)", value=st.session_state.victim_cfg.get("api_key","") if st.session_state.victim_cfg else "", type="password", key="modal_key")
            m_to = st.number_input("Timeout (s)", min_value=5, value=30, key="modal_timeout")
        btn_c1, btn_c2, btn_c3 = st.columns([1,1,1])
        with btn_c3:
            if st.button("Cancel", use_container_width=True):
                st.session_state.show_victim_modal = False
                st.rerun()
        with btn_c2:
            if st.button("Test & Save", type="primary", use_container_width=True):
                with st.spinner("Testing..."):
                    client = VictimClient(m_url.strip(), m_model.strip() or None, m_key.strip() or None, int(m_to))
                    ok, lat, detail = client.test_connection()
                    if ok:
                        st.session_state.victim_verified = True
                        st.session_state.victim_latency = lat
                        st.session_state.victim_cfg = {"webhook_url": m_url.strip(), "model_name": m_model.strip(), "api_key": m_key.strip(), "timeout": int(m_to)}
                        st.session_state.show_victim_modal = False
                        st.rerun()
                    else:
                        st.error(f"Failed: {detail}")


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN TABS
# ─────────────────────────────────────────────────────────────────────────────
tab_dash, tab_victim, tab_scope, tab_probes, tab_tool_abuse, tab_mutate, tab_execute, tab_report = st.tabs([
    "Dashboard",
    "Configure Target",
    "Define Scope",
    "Prompt Injection",
    "Tool Abuse Testing",
    "Mutation Engine",
    "Execute Attacks",
    "Security Report",
])


# ═════════════════════════════════════════════════════════════════════════════
#  TAB 1 — DASHBOARD
# ═════════════════════════════════════════════════════════════════════════════
with tab_dash:
    st.markdown(f'<div class="section-header">{_mi("dashboard", "mi-blue")} Mission Control</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">Live overview of your red-team operation.</div>', unsafe_allow_html=True)

    n_probes    = len(st.session_state.probe_results)
    n_vulns     = sum(1 for p in st.session_state.probe_results if p["vuln"])
    n_critical  = sum(1 for p in st.session_state.probe_results if p["severity"] == 5)
    n_mutations = len(st.session_state.mutated_prompts)
    n_ta_probes = len(st.session_state.ta_results)
    n_ta_vulns  = sum(1 for r in st.session_state.ta_results if r["vuln"])
    coverage    = st.session_state.probe_memory.coverage_pct if st.session_state.probe_memory else 0.0

    col1, col2, col3, col4, col5, col6 = st.columns(6)
    kpis = [
        (col1, str(n_probes),      "Probes Sent",          ""),
        (col2, str(n_vulns),       "Vulnerabilities",      "danger"),
        (col3, str(n_critical),    "Critical Findings",    "danger"),
        (col4, str(n_mutations),   "Mutated Prompts",      ""),
        (col5, str(n_ta_probes),   "Tool Abuse Probes",    ""),
        (col6, str(n_ta_vulns),    "Tool Abuse Hits",      "danger"),
    ]
    for col, val, lbl, cls in kpis:
        with col:
            st.markdown(f"""
            <div class="kpi-card {cls}">
                <div class="kpi-value">{val}</div>
                <div class="kpi-label">{lbl}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown('<div class="spacer-lg"></div>', unsafe_allow_html=True)

    left, right = st.columns([1.4, 1], gap="large")
    with left:
        st.markdown(f"#### {_mi('history', 'mi-blue')} Recent Activity", unsafe_allow_html=True)
        if st.session_state.probe_results:
            recent = st.session_state.probe_results[-8:][::-1]
            for p in recent:
                vuln_class = "vuln" if p["vuln"] else "safe"
                icon = _mi("warning", "mi-red") if p["vuln"] else _mi("check_circle", "mi-green")
                probe_snip = p["probe"][:90] + "..." if len(p["probe"]) > 90 else p["probe"]
                sev_html   = severity_badge(p["severity"])
                st.markdown(f"""
                <div class="probe-row {vuln_class}">
                    {icon} {sev_html} &nbsp; <span style="color:#1A1A2E;">{probe_snip}</span>
                    <br><span style="color:#6B7280; font-size:0.77rem; margin-top:4px; display:block;">
                        {_mi('label')} {p['weak_area']}  |  {p['insight'][:70]}
                    </span>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="rtf-card" style="text-align:center; padding: 2.5rem;">
                <div style="font-size:1.5rem; margin-bottom:0.5rem;">{_mi('search', 'mi-lg mi-blue')}</div>
                <div style="color:#6B7280;">No probes run yet. Head to <b>Prompt Injection</b> to start your first session.</div>
            </div>
            """, unsafe_allow_html=True)

    with right:
        st.markdown(f"#### {_mi('checklist', 'mi-blue')} Quick Status", unsafe_allow_html=True)
        victim_ok = st.session_state.victim_verified
        scope_ok  = len(st.session_state.scope_text.strip()) > 20
        probes_ok = n_probes > 0
        checks = [
            (victim_ok, "Target configured & verified"),
            (scope_ok,  "Scope / system prompt defined"),
            (probes_ok, "Probe session completed"),
            (n_mutations > 0, "Mutation engine run"),
            (n_ta_probes > 0, "Tool abuse testing run"),
            (len(st.session_state.attack_results) > 0, "Attack execution done"),
        ]
        for ok, label in checks:
            icon = _mi("check_circle", "mi-green") if ok else _mi("radio_button_unchecked")
            color = "#059669" if ok else "#9CA3AF"
            st.markdown(f'<div style="font-size:0.83rem; color:{color}; padding:0.3rem 0;">{icon} {label}</div>', unsafe_allow_html=True)


# ═════════════════════════════════════════════════════════════════════════════
#  TAB 2 — CONFIGURE TARGET
# ═════════════════════════════════════════════════════════════════════════════
with tab_victim:
    st.markdown(f'<div class="section-header">{_mi("gps_fixed", "mi-blue")} Configure Target LLM</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">Point RedTeamForge at any LLM endpoint --- Ollama, OpenAI, or a custom webhook.</div>', unsafe_allow_html=True)

    if st.session_state.victim_verified and st.session_state.victim_cfg:
        cfg = st.session_state.victim_cfg
        st.markdown(f"""
        <div class="conn-verified">
            <div>{_mi('check_circle', 'mi-lg mi-green')}</div>
            <div>
                <div style="font-weight:700; color:#059669; font-size:1rem;">Connection Verified</div>
                <div style="color:#6B7280; font-size:0.83rem; margin-top:2px;">
                    {cfg['webhook_url']} &nbsp;|&nbsp; {cfg.get('model_name','(no model)') or '(no model)'} &nbsp;|&nbsp;
                    {st.session_state.victim_latency:.0f}ms
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown('<div class="spacer-md"></div>', unsafe_allow_html=True)
        if st.button("Reconfigure Target", key="reconfigure_btn"):
            st.session_state.victim_verified = False
            st.session_state.victim_cfg = None
            st.rerun()

    st.markdown('<div class="rtf-card">', unsafe_allow_html=True)
    st.markdown("#### Endpoint Settings")
    col_a, col_b = st.columns([2, 1], gap="large")
    with col_a:
        webhook_url = st.text_input("Webhook URL *", value=st.session_state.victim_cfg["webhook_url"] if st.session_state.victim_cfg else "http://localhost:11434/api/generate", placeholder="https://api.openai.com/v1/chat/completions", key="victim_url_input")
        model_name = st.text_input("Model Name (optional)", value=st.session_state.victim_cfg.get("model_name","") if st.session_state.victim_cfg else "", placeholder="e.g. gemma3:latest, gpt-4o", key="victim_model_input")
    with col_b:
        api_key = st.text_input("API Key (optional)", value=st.session_state.victim_cfg.get("api_key","") if st.session_state.victim_cfg else "", type="password", key="victim_key_input")
        timeout = st.number_input("Timeout (seconds)", min_value=5, max_value=300, value=int(st.session_state.victim_cfg.get("timeout",30)) if st.session_state.victim_cfg else 30, step=5, key="victim_timeout_input")
    st.markdown("</div>", unsafe_allow_html=True)

    col_btn, col_status = st.columns([1, 3], gap="medium")
    with col_btn:
        test_clicked = st.button("Test Connection", type="primary", use_container_width=True, key="test_conn_btn")
    if test_clicked:
        if not webhook_url.strip():
            st.error("Please enter a Webhook URL.")
        else:
            with col_status:
                with st.spinner("Connecting..."):
                    client = VictimClient(webhook_url.strip(), model_name.strip() or None, api_key.strip() or None, int(timeout))
                    ok, latency_ms, detail = client.test_connection()
            if ok:
                st.session_state.victim_verified = True
                st.session_state.victim_latency  = latency_ms
                st.session_state.victim_cfg = {"webhook_url": webhook_url.strip(), "model_name": model_name.strip() or None, "api_key": api_key.strip() or None, "timeout": int(timeout)}
                st.success(f"Connection Verified! {detail}")
                st.rerun()
            else:
                st.error(f"Connection Failed: {detail}")


# ═════════════════════════════════════════════════════════════════════════════
#  TAB 3 — DEFINE SCOPE
# ═════════════════════════════════════════════════════════════════════════════
with tab_scope:
    st.markdown(f'<div class="section-header">{_mi("description", "mi-blue")} Define Target Scope</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">Paste the victim system prompt or describe what the model is supposed to do.</div>', unsafe_allow_html=True)

    col_scope, col_tips = st.columns([2, 1], gap="large")
    with col_scope:
        scope_text = st.text_area("System Prompt / Scope Description", value=st.session_state.scope_text, height=300, placeholder="Paste the victim's system prompt here...", key="scope_textarea")
        if scope_text != st.session_state.scope_text:
            st.session_state.scope_text = scope_text
        word_count = len(st.session_state.scope_text.split())
        st.caption(f"{word_count} words  |  {len(st.session_state.scope_text)} characters")

    with col_tips:
        st.markdown(f"""
        <div class="rtf-card">
            <div style="font-weight:700; color:#1A1A2E; margin-bottom:0.7rem;">{_mi('tips_and_updates', 'mi-blue')} Scope Tips</div>
            <div style="color:#6B7280; font-size:0.82rem; line-height:1.7;">
                <b style="color:#1A1A2E;">Include:</b><br>
                The model's role & purpose<br>
                Explicit restrictions<br>
                Any confidential info it should protect<br>
                Persona or character details<br><br>
                <b style="color:#1A1A2E;">Why it matters:</b><br>
                The attacker LLM reads this scope to craft probes targeting <i>your</i> model's constraints.
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(f"""
        <div class="rtf-card" style="margin-top:0.75rem;">
            <div style="font-weight:700; color:#1A1A2E; margin-bottom:0.5rem;">{_mi('category', 'mi-blue')} Taxonomy Coverage</div>
        """, unsafe_allow_html=True)
        for area in settings.WEAK_AREA_TAXONOMY:
            st.markdown(f'<span class="memory-tag-blue">{area}</span>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

        if st.button("Reset to Default Scope", key="reset_scope_btn"):
            st.session_state.scope_text = settings.DEFAULT_SCOPE_TEXT
            st.rerun()


# ═════════════════════════════════════════════════════════════════════════════
#  TAB 4 — PROMPT INJECTION (Run Probes)
# ═════════════════════════════════════════════════════════════════════════════
with tab_probes:
    st.markdown(f'<div class="section-header">{_mi("bug_report", "mi-blue")} Adaptive Probe Session</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">The AI attacker generates probes, sends them to your target, and the judge evaluates each response.</div>', unsafe_allow_html=True)

    ready = True
    if not st.session_state.victim_verified:
        st.warning("Target not configured. Head to the Configure Target tab first.")
        ready = False
    if not st.session_state.scope_text.strip():
        st.warning("Scope is empty. Define the target scope first.")
        ready = False

    # Feature toggles
    toggle_col1, toggle_col2, toggle_col3 = st.columns([1, 1, 2])
    with toggle_col1:
        st.session_state.enable_multi_turn = st.toggle("Multi-Turn Probing", value=st.session_state.enable_multi_turn, key="toggle_multi_turn")
    with toggle_col2:
        st.session_state.enable_tool_abuse = st.toggle("Tool Abuse Testing", value=st.session_state.enable_tool_abuse, key="toggle_tool_abuse")
    with toggle_col3:
        if st.session_state.current_step:
            st.caption(f"⏳ Current Step: {st.session_state.current_step}")

    if st.session_state.probe_running:
        _drain_probe_queue()

    probe_col, memory_col = st.columns([2, 1], gap="large")

    with memory_col:
        st.markdown(f"#### {_mi('psychology', 'mi-blue')} Session Memory", unsafe_allow_html=True)
        mem: ProbeMemory = st.session_state.probe_memory
        if mem:
            cov = mem.coverage_pct
            st.markdown(f"**Taxonomy Coverage: {cov:.0f}%**")
            st.progress(cov / 100)
            st.markdown(f"""
            <div class="memory-section">
                <div style="font-size:0.75rem; color:#6B7280; font-weight:600; letter-spacing:0.08em; text-transform:uppercase; margin-bottom:0.5rem;">
                    Weak Areas ({len(mem.weak_areas)})
                </div>
                {"".join(f'<span class="memory-tag">{w}</span>' for w in mem.weak_areas) or '<span style="color:#9CA3AF;font-size:0.8rem;">None yet</span>'}
            </div>
            """, unsafe_allow_html=True)
            st.markdown(f"""
            <div class="memory-section">
                <div style="font-size:0.75rem; color:#6B7280; font-weight:600; letter-spacing:0.08em; text-transform:uppercase; margin-bottom:0.5rem;">
                    Strong Areas ({len(mem.strong_areas)})
                </div>
                {"".join(f'<span class="memory-tag-green">{s}</span>' for s in mem.strong_areas) or '<span style="color:#9CA3AF;font-size:0.8rem;">None yet</span>'}
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="rtf-card" style="text-align:center; padding:1.5rem;">
                <div style="color:#9CA3AF; font-size:0.85rem;">Memory initializes when session starts.</div>
            </div>
            """, unsafe_allow_html=True)

    with probe_col:
        ctrl_left, ctrl_right = st.columns(2, gap="medium")
        with ctrl_left:
            max_probes_val = st.number_input("Max Probes", min_value=3, max_value=100, value=settings.MAX_PROBES_PER_SESSION, step=1, key="max_probes_input")
        with ctrl_right:
            max_mins_val = st.number_input("Time Limit (mins)", min_value=1, max_value=60, value=settings.MAX_SESSION_MINUTES, step=1, key="max_mins_input")

        col_start, col_stop, col_clear = st.columns([2, 1, 1], gap="small")
        with col_start:
            start_disabled = (not ready) or st.session_state.probe_running
            if st.button("Start Adaptive Probe Session" if not st.session_state.probe_running else "Session Running...", type="primary", disabled=start_disabled, use_container_width=True, key="start_probe_btn"):
                sid    = _new_session_id()
                memory = ProbeMemory()
                q      = Queue()
                st.session_state.session_id      = sid
                st.session_state.probe_memory    = memory
                st.session_state.probe_queue     = q
                st.session_state.probe_results   = []
                st.session_state.probe_running   = True
                st.session_state.probe_stop_reason = None
                runner = ProbeRunner(session_id=sid, scope_text=st.session_state.scope_text, victim_cfg=st.session_state.victim_cfg, memory=memory, max_probes=int(max_probes_val), max_minutes=int(max_mins_val))
                st.session_state.probe_runner = runner
                runner.start(q)
                st.rerun()
        with col_stop:
            if st.button("Stop", disabled=not st.session_state.probe_running, use_container_width=True, key="stop_probe_btn"):
                if st.session_state.probe_runner:
                    st.session_state.probe_runner.stop()
                st.session_state.probe_running = False
                st.session_state.probe_stop_reason = "Manually stopped"
                st.rerun()
        with col_clear:
            if st.button("Clear", use_container_width=True, key="clear_probe_btn", disabled=st.session_state.probe_running):
                st.session_state.probe_results = []
                st.session_state.probe_memory = None
                st.session_state.session_id = None
                st.session_state.probe_stop_reason = None
                st.rerun()

        st.markdown('<div class="spacer-md"></div>', unsafe_allow_html=True)

        n_done = len(st.session_state.probe_results)
        if st.session_state.probe_running or n_done > 0:
            pct = min(1.0, n_done / int(max_probes_val))
            st.progress(pct)
            st.caption(f"{n_done}/{int(max_probes_val)} probes completed")
            if st.session_state.probe_running:
                st.markdown(f'<span class="live-dot"></span><span style="color:#2563EB; font-size:0.85rem; font-weight:600;">Probing in progress...</span>', unsafe_allow_html=True)

        if st.session_state.probe_stop_reason:
            st.info(f"Session ended: {st.session_state.probe_stop_reason}")

        st.markdown("#### Probe Results")
        if st.session_state.probe_results:
            rows = []
            for i, p in enumerate(reversed(st.session_state.probe_results), 1):
                rows.append({"#": len(st.session_state.probe_results) - i + 1, "Probe": p["probe"][:80], "Severity": p["severity"], "Weak Area": p["weak_area"], "Vuln?": "YES" if p["vuln"] else "No"})
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.markdown('<div class="rtf-card" style="text-align:center; padding:2rem;"><div style="color:#9CA3AF;">Results will appear here as probes are run.</div></div>', unsafe_allow_html=True)

        # Conversation log for multi-turn
        if st.session_state.conversation_log:
            with st.expander(f"📜 Conversation Log ({len(st.session_state.conversation_log)} entries)", expanded=False):
                for entry in reversed(st.session_state.conversation_log[-20:]):
                    role_icon = "🔴" if entry.get("role") == "attacker" else "🟢" if entry.get("role") == "victim" else "⚖️"
                    st.markdown(f"**{role_icon} {entry.get('role', 'unknown').title()}** — Turn {entry.get('turn', '?')}")
                    st.text(entry.get("text", "")[:300])
                    if entry.get("judgment"):
                        j = entry["judgment"]
                        sev_txt = f"Severity: {j}" if isinstance(j, (int, float)) else str(j)[:100]
                        st.caption(sev_txt)
                    st.divider()

    if st.session_state.probe_running:
        time.sleep(1.2)
        st.rerun()


# ═════════════════════════════════════════════════════════════════════════════
#  TAB 5 — TOOL ABUSE TESTING (NEW)
# ═════════════════════════════════════════════════════════════════════════════
with tab_tool_abuse:
    st.markdown(f'<div class="section-header">{_mi("build_circle", "mi-blue")} Agentic Tool Abuse Testing</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">Multi-turn testing of LLM tool-calling security. Uses Thompson Sampling for intelligent probe selection and adaptive escalation.</div>', unsafe_allow_html=True)

    if st.session_state.ta_running:
        _drain_ta_queue()

    # ── Configuration Panel ──
    ta_config_col, ta_info_col = st.columns([2, 1], gap="large")

    with ta_info_col:
        st.markdown(f"""
        <div class="rtf-card">
            <div style="font-weight:700; color:#1A1A2E; margin-bottom:0.7rem;">{_mi('info', 'mi-blue')} How It Works</div>
            <div style="color:#6B7280; font-size:0.82rem; line-height:1.8;">
                <b>1. Thompson Sampling</b> selects which attack vector to try next, balancing exploration with exploitation.<br><br>
                <b>2. Multi-turn conversations</b> simulate realistic attack scenarios with context priming and gradual escalation.<br><br>
                <b>3. Memory layer</b> tracks per-vector success rates, tool vulnerability scores, and discovered patterns.<br><br>
                <b>4. Smart mutation</b> adapts follow-up probes based on what the target refused vs. allowed.
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Memory panel
        ta_mem: ToolAbuseMemory = st.session_state.ta_memory
        if ta_mem and ta_mem.total_probes > 0:
            st.markdown(f"#### {_mi('memory', 'mi-blue')} Attack Memory", unsafe_allow_html=True)
            st.markdown(f"**Vector Coverage: {ta_mem.vector_coverage:.0f}%**")
            st.progress(ta_mem.vector_coverage / 100)
            st.markdown(f"**Tool Coverage: {ta_mem.tool_coverage:.0f}%**")
            st.progress(ta_mem.tool_coverage / 100)

            if ta_mem.weak_vectors:
                st.markdown('<div class="memory-section">', unsafe_allow_html=True)
                st.markdown('<div style="font-size:0.75rem; color:#DC2626; font-weight:600; text-transform:uppercase; margin-bottom:0.3rem;">Weak Vectors</div>', unsafe_allow_html=True)
                for v in ta_mem.weak_vectors:
                    st.markdown(f'<span class="memory-tag">{v}</span>', unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)

            if ta_mem.key_findings:
                st.markdown('<div class="memory-section">', unsafe_allow_html=True)
                st.markdown('<div style="font-size:0.75rem; color:#6B7280; font-weight:600; text-transform:uppercase; margin-bottom:0.3rem;">Key Findings</div>', unsafe_allow_html=True)
                for f in ta_mem.key_findings[-5:]:
                    st.markdown(f'<div style="font-size:0.78rem; color:#1A1A2E; padding:0.2rem 0; border-bottom:1px solid #E5E7EB;">- {f[:80]}</div>', unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)

    with ta_config_col:
        # Pre-flight
        ta_ready = True
        if not st.session_state.victim_verified:
            st.warning("Target not configured. Configure a victim endpoint first.")
            ta_ready = False

        st.markdown("##### Target Tools")
        st.caption("Comma-separated list of tools available on the target LLM.")
        ta_tools_str = st.text_input("Available Tools", value=st.session_state.ta_tools, key="ta_tools_input", label_visibility="collapsed")
        st.session_state.ta_tools = ta_tools_str

        st.markdown('<div class="spacer-sm"></div>', unsafe_allow_html=True)

        st.markdown("##### Attack Vectors")
        vec_cols = st.columns(5)
        selected_vecs = []
        for i, vec in enumerate(TOOL_ABUSE_VECTORS):
            with vec_cols[i % 5]:
                if st.checkbox(vec.replace("_", " ").title(), value=vec in st.session_state.ta_vectors, key=f"ta_vec_{vec}"):
                    selected_vecs.append(vec)
        st.session_state.ta_vectors = selected_vecs

        st.markdown('<div class="spacer-sm"></div>', unsafe_allow_html=True)

        st.markdown("##### Session Settings")
        ta_set_cols = st.columns(3, gap="medium")
        with ta_set_cols[0]:
            ta_max_probes = st.number_input("Max Probes", min_value=3, max_value=100, value=settings.TOOL_ABUSE_MAX_PROBES, key="ta_max_probes")
        with ta_set_cols[1]:
            ta_max_turns = st.number_input("Turns per Conversation", min_value=1, max_value=10, value=settings.TOOL_ABUSE_MAX_TURNS, key="ta_max_turns")
        with ta_set_cols[2]:
            ta_max_convs = st.number_input("Max Conversations", min_value=1, max_value=20, value=settings.TOOL_ABUSE_MAX_CONVERSATIONS, key="ta_max_convs")

        st.markdown('<div class="spacer-md"></div>', unsafe_allow_html=True)

        # Controls
        ta_ctrl1, ta_ctrl2, ta_ctrl3 = st.columns([2, 1, 1], gap="small")
        with ta_ctrl1:
            ta_start_disabled = (not ta_ready) or st.session_state.ta_running or not selected_vecs
            if st.button(
                "Start Tool Abuse Testing" if not st.session_state.ta_running else "Testing Running...",
                type="primary", disabled=ta_start_disabled, use_container_width=True, key="ta_start_btn"
            ):
                ta_mem = ToolAbuseMemory()
                ta_tools_list = [t.strip() for t in ta_tools_str.split(",") if t.strip()]
                ta_mem.initialize(tools=ta_tools_list, vectors=selected_vecs)
                ta_q = Queue()

                st.session_state.ta_memory = ta_mem
                st.session_state.ta_queue = ta_q
                st.session_state.ta_results = []
                st.session_state.ta_running = True
                st.session_state.ta_stop_reason = None

                if not st.session_state.session_id:
                    st.session_state.session_id = _new_session_id()

                cfg = st.session_state.victim_cfg
                ta_runner = ToolAbuseRunner(
                    session_id=st.session_state.session_id,
                    webhook_url=cfg["webhook_url"],
                    memory=ta_mem,
                    available_tools=ta_tools_list,
                    enabled_vectors=selected_vecs,
                    max_probes=int(ta_max_probes),
                    max_turns_per_conversation=int(ta_max_turns),
                    max_conversations=int(ta_max_convs),
                    judge_model=st.session_state.judge_model,
                    model_name=cfg.get("model_name"),
                    api_key=cfg.get("api_key"),
                    timeout=int(cfg.get("timeout", 60)),
                )
                st.session_state.ta_runner = ta_runner
                ta_runner.start(ta_q)
                st.rerun()

        with ta_ctrl2:
            if st.button("Stop", disabled=not st.session_state.ta_running, use_container_width=True, key="ta_stop_btn"):
                if st.session_state.ta_runner:
                    st.session_state.ta_runner.stop()
                st.session_state.ta_running = False
                st.session_state.ta_stop_reason = "Manually stopped"
                st.rerun()

        with ta_ctrl3:
            if st.button("Clear", use_container_width=True, key="ta_clear_btn", disabled=st.session_state.ta_running):
                st.session_state.ta_results = []
                st.session_state.ta_memory = None
                st.session_state.ta_stop_reason = None
                st.rerun()

        st.markdown('<div class="spacer-md"></div>', unsafe_allow_html=True)

        # Progress
        n_ta_done = len(st.session_state.ta_results)
        if st.session_state.ta_running or n_ta_done > 0:
            pct = min(1.0, n_ta_done / int(ta_max_probes)) if ta_max_probes > 0 else 0
            st.progress(pct)
            st.caption(f"{n_ta_done}/{int(ta_max_probes)} probes completed")
            if st.session_state.ta_running:
                st.markdown(f'<span class="live-dot"></span><span style="color:#2563EB; font-size:0.85rem; font-weight:600;">Tool abuse testing in progress...</span>', unsafe_allow_html=True)

        if st.session_state.ta_stop_reason:
            st.info(f"Session ended: {st.session_state.ta_stop_reason}")

        # Results
        st.markdown(f"#### {_mi('table_chart', 'mi-blue')} Tool Abuse Results", unsafe_allow_html=True)
        if st.session_state.ta_results:
            ta_rows = []
            for i, r in enumerate(reversed(st.session_state.ta_results), 1):
                ta_rows.append({
                    "#": len(st.session_state.ta_results) - i + 1,
                    "Turn": r["turn"],
                    "Vector": r["vector"].replace("_", " ").title(),
                    "Probe": r["probe"][:70] + "..." if len(r["probe"]) > 70 else r["probe"],
                    "Severity": f"{r['severity']:.2f}",
                    "Category": r["category"],
                    "Tools": r["tools"] or "---",
                    "Vuln?": "YES" if r["vuln"] else "No",
                })
            ta_df = pd.DataFrame(ta_rows)
            st.dataframe(ta_df, use_container_width=True, hide_index=True)

            # Detailed view
            st.markdown('<div class="spacer-md"></div>', unsafe_allow_html=True)
            st.markdown(f"#### {_mi('visibility', 'mi-blue')} Detailed Findings", unsafe_allow_html=True)
            vuln_results = [r for r in st.session_state.ta_results if r["vuln"]]
            if vuln_results:
                for i, r in enumerate(vuln_results[:10], 1):
                    sev_pct = int(r["severity"] * 100)
                    with st.expander(f"Finding #{i} | {r['category']} | Severity: {sev_pct}% | {r['vector']}"):
                        fc1, fc2 = st.columns([1, 1])
                        with fc1:
                            st.markdown("**Attack Probe**")
                            st.code(r["probe"], language=None)
                        with fc2:
                            st.markdown("**Finding**")
                            st.markdown(f"**Category:** `{r['category']}`")
                            st.markdown(f"**Tools Involved:** `{r['tools']}`")
                            st.markdown(f"**Key Finding:** {r['finding']}")
                        if r.get("tool_calls"):
                            st.markdown("**Tool Call Trace:**")
                            st.json(r["tool_calls"][:5])
            else:
                st.success("No tool abuse vulnerabilities found. The target defended well.")
        else:
            st.markdown(f'<div class="rtf-card" style="text-align:center; padding:2rem;"><div style="color:#9CA3AF;">Results will appear here as tool abuse probes are run.</div></div>', unsafe_allow_html=True)

    if st.session_state.ta_running:
        time.sleep(1.2)
        st.rerun()


# ═════════════════════════════════════════════════════════════════════════════
#  TAB 6 — MUTATION ENGINE
# ═════════════════════════════════════════════════════════════════════════════
with tab_mutate:
    st.markdown(f'<div class="section-header">{_mi("genetics", "mi-blue")} Mutation Engine</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">Evolve high-severity probes into more sophisticated attack variants using persona-driven genetic mutation.</div>', unsafe_allow_html=True)

    mut_left, mut_right = st.columns([1.6, 1], gap="large")
    with mut_right:
        st.markdown(f"""
        <div class="rtf-card">
            <div style="font-weight:700; color:#1A1A2E; margin-bottom:0.7rem;">{_mi('science', 'mi-blue')} How it works</div>
            <div style="color:#6B7280; font-size:0.82rem; line-height:1.8;">
                1. Selects the highest-severity probes from your session.<br>
                2. Chooses a random attacker <b>persona</b>.<br>
                3. Instructs the LLM to produce more sophisticated variants.<br>
                4. Saves all child prompts to the database.
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown(f"""
        <div class="rtf-card">
            <div style="font-weight:700; color:#1A1A2E; margin-bottom:0.5rem;">{_mi('tune', 'mi-blue')} Settings</div>
        """, unsafe_allow_html=True)
        n_mutations = st.number_input("Prompts to generate", min_value=2, max_value=40, value=settings.MUTATION_BATCH_SIZE, step=1, key="n_mutations_input")
        top_parents = st.number_input("Parent probes to use", min_value=1, max_value=20, value=settings.TOP_GENOMES_TO_SELECT, step=1, key="top_parents_input")
        st.markdown("</div>", unsafe_allow_html=True)

    with mut_left:
        if st.button("Load Parent Probes from DB", key="load_parents_btn"):
            try:
                with get_session() as db:
                    parents = mutator.get_parent_probes_from_db(db, limit=int(top_parents))
                st.session_state.mutation_parents = parents
            except Exception as e:
                st.error(f"Could not load parents: {e}")

        if st.session_state.mutation_parents:
            st.markdown(f"**{len(st.session_state.mutation_parents)} parent prompts selected**")
            for i, p in enumerate(st.session_state.mutation_parents, 1):
                sev_html = severity_badge(p.get("severity", 0))
                st.markdown(f"""
                <div class="probe-row vuln">
                    {sev_html} &nbsp; <b>#{i}</b>&nbsp;
                    <span style="color:#1A1A2E;">{p['probe_text'][:100]}...</span>
                </div>
                """, unsafe_allow_html=True)

        st.markdown('<div class="spacer-md"></div>', unsafe_allow_html=True)
        gen_disabled = len(st.session_state.mutation_parents) == 0
        if st.button("Generate Mutated Prompts", type="primary", disabled=gen_disabled, use_container_width=True, key="generate_mutations_btn"):
            parents = st.session_state.mutation_parents
            mem = st.session_state.probe_memory
            wa_list = mem.weak_areas if mem else []
            with st.spinner(f"Generating {int(n_mutations)} mutated prompts..."):
                try:
                    new_prompts = mutator.mutate_probes(parent_probes=parents, weak_areas=wa_list, n=int(n_mutations))
                    st.session_state.mutated_prompts = new_prompts
                    sid = st.session_state.session_id
                    if sid and new_prompts:
                        with get_session() as db:
                            for txt in new_prompts:
                                row = MutatedPromptDB(session_id=sid, prompt_text=txt, persona_used="auto", weak_areas=wa_list)
                                db.add(row)
                    st.rerun()
                except Exception as e:
                    st.error(f"Mutation failed: {e}")

        if st.session_state.mutated_prompts:
            st.markdown(f"#### {len(st.session_state.mutated_prompts)} Mutated Prompts Generated")
            for i, txt in enumerate(st.session_state.mutated_prompts, 1):
                with st.expander(f"Mutation #{i} --- {txt[:60]}..."):
                    st.code(txt, language=None)


# ═════════════════════════════════════════════════════════════════════════════
#  TAB 7 — EXECUTE ATTACKS
# ═════════════════════════════════════════════════════════════════════════════
with tab_execute:
    st.markdown(f'<div class="section-header">{_mi("bolt", "mi-blue")} Execute Attack Batch</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">Fire all mutated prompts at the target and collect real results.</div>', unsafe_allow_html=True)

    if not st.session_state.victim_verified:
        st.warning("Configure and verify your target endpoint first.")
    elif not st.session_state.mutated_prompts:
        st.warning("No mutated prompts available. Run the Mutation Engine first.")
    else:
        exec_left, exec_right = st.columns([2, 1], gap="large")
        with exec_right:
            st.markdown(f"""
            <div class="kpi-card" style="text-align:center;">
                <div class="kpi-value">{len(st.session_state.mutated_prompts)}</div>
                <div class="kpi-label">Prompts Ready</div>
            </div>
            """, unsafe_allow_html=True)

        with exec_left:
            if st.button("Execute All Attacks", type="primary", use_container_width=True, key="execute_attacks_btn"):
                cfg     = st.session_state.victim_cfg
                client  = VictimClient(**cfg)
                results = []
                progress_bar = st.progress(0)
                status_text  = st.empty()
                n_total      = len(st.session_state.mutated_prompts)
                from rtf_core.judge import evaluate as judge_evaluate, Judgment
                for i, prompt_text in enumerate(st.session_state.mutated_prompts):
                    status_text.markdown(f'<span class="live-dot"></span> Executing prompt {i+1}/{n_total}...', unsafe_allow_html=True)
                    ok, response = client.send(prompt_text)
                    if ok:
                        j = judge_evaluate(prompt_text, response)
                    else:
                        j = Judgment(False, None, "Unreachable", 1, None)
                        response = f"[Connection error: {response}]"
                    results.append({"prompt": prompt_text, "response": response, "vuln": j.vulnerability_found, "weak_area": j.weak_area or "---", "severity": j.severity, "insight": j.key_insight})
                    progress_bar.progress((i + 1) / n_total)
                st.session_state.attack_results = results
                status_text.markdown("Execution complete!")
                st.rerun()

            if st.session_state.attack_results:
                st.markdown("#### Attack Execution Results")
                df_rows = [{"#": i, "Prompt": r["prompt"][:70], "Vuln?": "YES" if r["vuln"] else "No", "Severity": r["severity"], "Weak Area": r["weak_area"]} for i, r in enumerate(st.session_state.attack_results, 1)]
                st.dataframe(pd.DataFrame(df_rows), use_container_width=True, hide_index=True)


# ═════════════════════════════════════════════════════════════════════════════
#  TAB 8 — SECURITY REPORT
# ═════════════════════════════════════════════════════════════════════════════
with tab_report:
    st.markdown(f'<div class="section-header">{_mi("assessment", "mi-blue")} Security Report</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">Executive summary with risk scoring, vulnerability evidence, and PDF export.</div>', unsafe_allow_html=True)

    if not st.session_state.session_id:
        st.warning("No active session. Complete a probe run first.")
    else:
        col_name, col_gen = st.columns([2, 1], gap="medium")
        with col_name:
            session_name = st.text_input("Session Name", value=f"Red Team --- {datetime.datetime.now().strftime('%Y-%m-%d')}", key="report_name_input")
        with col_gen:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("Generate Report", type="primary", use_container_width=True, key="gen_report_btn"):
                try:
                    with get_session() as db:
                        sess = db.query(SessionDB).filter_by(session_id=st.session_state.session_id).first()
                        if sess:
                            sess.name = session_name
                            if not sess.end_time:
                                sess.end_time = datetime.datetime.utcnow()
                            if st.session_state.probe_memory:
                                sess.memory_snapshot = st.session_state.probe_memory.to_dict()
                                sess.vulnerabilities = st.session_state.probe_memory.finding_count
                                sess.total_probes    = st.session_state.probe_memory.probe_count
                except Exception:
                    pass
                with st.spinner("Aggregating results..."):
                    rd = report_builder.build_report(st.session_state.session_id)
                    st.session_state.report_data = rd
                st.rerun()

        rd = st.session_state.report_data
        if rd and not rd.get("error"):
            risk  = rd.get("risk_score", 0)
            total = rd.get("total_probes", 0)
            vulns = rd.get("vuln_count", 0)

            if   risk >= 75:  risk_col, risk_lbl = "#DC2626", "CRITICAL RISK"
            elif risk >= 50:  risk_col, risk_lbl = "#EA580C", "HIGH RISK"
            elif risk >= 25:  risk_col, risk_lbl = "#D97706", "MEDIUM RISK"
            else:             risk_col, risk_lbl = "#059669", "LOW RISK"

            rep_left, rep_center, rep_right = st.columns([1, 1, 1], gap="large")
            with rep_center:
                st.markdown(f"""
                <div class="risk-gauge-wrap">
                    <div class="risk-score-big" style="color:{risk_col};">{risk}</div>
                    <div style="font-size:1rem; font-weight:700; color:{risk_col}; margin-top:0.25rem;">{risk_lbl}</div>
                    <div class="risk-label">Overall Risk Score (0-100)</div>
                </div>
                """, unsafe_allow_html=True)
            with rep_left:
                st.markdown(f"""
                <div class="kpi-card" style="margin-top:1.5rem;"><div class="kpi-value">{total}</div><div class="kpi-label">Total Probes</div></div>
                <div class="kpi-card danger"><div class="kpi-value">{vulns}</div><div class="kpi-label">Vulnerabilities</div></div>
                """, unsafe_allow_html=True)

            st.markdown('<hr class="rtf-divider">', unsafe_allow_html=True)

            # PDF export
            st.markdown("#### Export Report")
            try:
                pdf_bytes = generate_pdf(rd)
                fname = f"RedTeamForge_Report_{datetime.date.today()}.pdf"
                st.download_button(label="Download PDF Report", data=pdf_bytes, file_name=fname, mime="application/pdf", use_container_width=False, type="primary", key="download_pdf_btn")
            except Exception as e:
                st.error(f"PDF generation failed: {e}")

        elif rd and rd.get("error"):
            st.error(rd["error"])
        else:
            st.markdown(f"""
            <div class="rtf-card" style="text-align:center; padding:3rem;">
                <div style="font-size:1.5rem; margin-bottom:0.75rem;">{_mi('assessment', 'mi-lg mi-blue')}</div>
                <div style="color:#6B7280;">Click <b>Generate Report</b> to aggregate your session findings into an executive summary.</div>
            </div>
            """, unsafe_allow_html=True)
