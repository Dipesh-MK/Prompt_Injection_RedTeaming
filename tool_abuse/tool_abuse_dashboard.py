import sys
sys.stdout.reconfigure(encoding='utf-8')

import streamlit as st
import pandas as pd
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool
import plotly.express as px
import plotly.graph_objects as go
import re


# =========================
# CONFIG
# =========================
DB_URI = "postgresql://incharakandgal@localhost:5432/redteam_db"

st.set_page_config(
    page_title="Tool Abuse Analytics",
    page_icon="🛠️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =========================
# CUSTOM CSS
# =========================

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');

    html, body, [class*="css"] {
        font-family: 'Syne', sans-serif;
        background-color: #0a0a0f;
        color: #e2e2e2;
    }

    .stApp { background-color: #0a0a0f; }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #0f0f1a;
        border-right: 1px solid #1e1e3a;
    }

    /* Metric cards */
    [data-testid="metric-container"] {
        background: linear-gradient(135deg, #0f0f1a 0%, #141428 100%);
        border: 1px solid #1e1e3a;
        border-radius: 12px;
        padding: 16px;
    }
    [data-testid="metric-container"] label {
        color: #6e6e9e !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 11px !important;
        text-transform: uppercase;
        letter-spacing: 2px;
    }
    [data-testid="metric-container"] [data-testid="stMetricValue"] {
        color: #e040fb !important;
        font-family: 'Syne', sans-serif !important;
        font-size: 2.2rem !important;
        font-weight: 800 !important;
    }

    /* Headers */
    h1 {
        font-family: 'Syne', sans-serif !important;
        font-weight: 800 !important;
        color: #ffffff !important;
        letter-spacing: -1px;
    }
    h2, h3 {
        font-family: 'Syne', sans-serif !important;
        color: #c0c0e0 !important;
    }

    /* Dataframe */
    .stDataFrame {
        border: 1px solid #1e1e3a;
        border-radius: 8px;
        overflow: hidden;
    }

    /* Selectbox, multiselect */
    .stSelectbox > div, .stMultiSelect > div {
        background-color: #0f0f1a !important;
        border: 1px solid #1e1e3a !important;
        border-radius: 8px !important;
        color: #e2e2e2 !important;
    }

    /* Slider */
    .stSlider > div { color: #e2e2e2; }

    /* Expander */
    .streamlit-expanderHeader {
        background-color: #0f0f1a !important;
        border: 1px solid #1e1e3a !important;
        border-radius: 8px !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 12px !important;
        color: #c0c0e0 !important;
    }
    .streamlit-expanderContent {
        background-color: #0a0a0f !important;
        border: 1px solid #1e1e3a !important;
        border-top: none !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 12px !important;
    }

    /* Badge styles */
    .badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 20px;
        font-size: 11px;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 700;
        letter-spacing: 0.5px;
        margin: 2px;
    }
    .badge-critical { background: #3d0000; color: #ff4444; border: 1px solid #ff4444; }
    .badge-high     { background: #2d1a00; color: #ff9944; border: 1px solid #ff9944; }
    .badge-medium   { background: #2d2d00; color: #ffdd44; border: 1px solid #ffdd44; }
    .badge-low      { background: #002d00; color: #44ff88; border: 1px solid #44ff88; }
    .badge-none     { background: #1a1a2e; color: #6e6e9e; border: 1px solid #6e6e9e; }
    .badge-category { background: #1a0a2e; color: #c084fc; border: 1px solid #7c3aed; }
    .badge-success  { background: #0d2d1a; color: #4ade80; border: 1px solid #22c55e; }
    .badge-fail     { background: #2d0d0d; color: #f87171; border: 1px solid #ef4444; }

    /* Prompt card */
    .prompt-card {
        background: linear-gradient(135deg, #0f0f1a 0%, #141428 100%);
        border: 1px solid #1e1e3a;
        border-radius: 12px;
        padding: 16px 20px;
        margin: 8px 0;
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
        line-height: 1.6;
    }
    .prompt-text {
        color: #a0a0c0;
        word-break: break-word;
        white-space: pre-wrap;
    }
    .response-text {
        color: #c0e0c0;
        word-break: break-word;
        white-space: pre-wrap;
        border-left: 2px solid #22c55e;
        padding-left: 10px;
        margin-top: 8px;
    }

    /* Title bar */
    .title-bar {
        background: linear-gradient(90deg, #1a0a2e 0%, #0a0a1e 100%);
        border-bottom: 1px solid #2e1e4e;
        padding: 20px 0 16px 0;
        margin-bottom: 24px;
    }

    /* Divider */
    hr { border-color: #1e1e3a !important; }

    /* Input */
    .stTextInput > div > div {
        background-color: #0f0f1a !important;
        border: 1px solid #1e1e3a !important;
        color: #e2e2e2 !important;
        border-radius: 8px !important;
    }

    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #0f0f1a;
        border: 1px solid #1e1e3a;
        border-radius: 8px 8px 0 0;
        color: #6e6e9e;
        font-family: 'JetBrains Mono', monospace;
        font-size: 13px;
        padding: 8px 20px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #1a0a2e !important;
        border-color: #7c3aed !important;
        color: #e040fb !important;
    }
</style>
""", unsafe_allow_html=True)


# =========================
# PLOTLY THEME
# =========================

CHART_COLORS = ["#7c3aed", "#e040fb", "#06b6d4", "#f59e0b", "#ef4444",
                "#22c55e", "#8b5cf6", "#ec4899", "#14b8a6", "#f97316"]

CHART_LAYOUT = dict(
    paper_bgcolor="#0a0a0f",
    plot_bgcolor="#0f0f1a",
    font=dict(family="JetBrains Mono", color="#c0c0e0", size=11),
    margin=dict(l=0, r=0, t=30, b=0),
    legend=dict(bgcolor="#0f0f1a", bordercolor="#1e1e3a", borderwidth=1),
)

GRID_COLOR = "#1e1e3a"


# =========================
# DB LOADER
# =========================

PROMPT_INTENT_PATTERNS = [
    (r"(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE).{0,50}(FROM|INTO|TABLE)", "database_query"),
    (r"(query|search|lookup|fetch|retrieve).{0,30}(database|db|table|record|row)", "database_query"),
    (r"(show|list|dump|export).{0,30}(users|customers|accounts|records|data)",    "database_query"),
    (r"(read|open|write|delete|list).{0,30}(file|directory|folder|path|disk)",   "file_system"),
    (r"(cat |ls |pwd |cd |rm |cp |mv |chmod|chown)",                             "file_system"),
    (r"(\/etc\/passwd|\/etc\/shadow|\.ssh|\.env|config\.yml)",                   "file_system"),
    (r"(execute|run|eval|compile|interpret).{0,30}(code|script|command|shell)",  "code_execution"),
    (r"(os\.system|subprocess|exec\(|eval\(|shell=True)",                        "code_execution"),
    (r"(python|bash|powershell|cmd|terminal|console).{0,20}(run|execute|script)","code_execution"),
    (r"(fetch|request|crawl|scrape|download).{0,30}(url|website|http|api)",      "web_request"),
    (r"(send|post|get|put|delete).{0,20}(request|http|api|endpoint|webhook)",    "web_request"),
    (r"(exfiltrate|leak|send).{0,30}(to|via).{0,20}(url|webhook|server|http)",   "web_request"),
    (r"(send|compose|write|draft).{0,20}(email|mail|message|sms|text)",          "email_messaging"),
    (r"(smtp|imap|outlook|gmail|mailgun|sendgrid)",                              "email_messaging"),
    (r"(password|credential|token|api.key|secret|auth).{0,30}(steal|get|leak|dump|extract)", "credential_theft"),
    (r"(bypass|skip|ignore|override).{0,20}(auth|login|password|security|2fa)",  "credential_theft"),
    (r"(brute.?force|crack|hash|rainbow.table)",                                 "credential_theft"),
    (r"(remember|store|save|recall).{0,20}(this|that|following|information)",    "memory_manipulation"),
    (r"(forget|ignore|override|replace).{0,20}(previous|prior|earlier|context)", "memory_manipulation"),
    (r"(your (memory|context|history|previous instructions))",                   "memory_manipulation"),
    (r"(system|os|kernel|process|registry|service).{0,20}(call|access|modify|kill|spawn)", "system_access"),
    (r"(reboot|shutdown|restart|kill process|terminate)",                        "system_access"),
    (r"(environment variable|PATH|PYTHONPATH|LD_PRELOAD)",                       "system_access"),
    (r"(exfiltrate|steal|leak|extract|export).{0,30}(data|information|records|config)", "data_exfiltration"),
    (r"(send|transmit|upload).{0,20}(sensitive|private|confidential|secret)",    "data_exfiltration"),
    (r"(admin|root|superuser|sudo|elevated|privileged).{0,20}(access|rights|permission|mode)", "privilege_escalation"),
    (r"(escalate|elevate|gain|obtain).{0,20}(privilege|permission|access|rights)", "privilege_escalation"),
]

def classify_prompt_intent(prompt_text: str) -> str:
    if not isinstance(prompt_text, str): return "none"
    lower = prompt_text.lower()
    for pattern, intent in PROMPT_INTENT_PATTERNS:
        if re.search(pattern, lower, re.IGNORECASE):
            return intent
    return "none"

@st.cache_data(ttl=60)
def load_data():
    engine = create_engine(DB_URI, poolclass=NullPool)
    with engine.connect() as conn:
        df = pd.read_sql("""
            SELECT
                p.id::text               AS prompt_id,
                p.prompt_text,
                p.vector                 AS attack_technique,
                t.name                   AS tool_call_type,
                p.injected_payload,
                r.id::text               AS eval_id,
                r.llm_response           AS llm_output,
                r.target_model           AS model_name,
                r.success_flag,
                r.leak_type              AS attack_category,
                r.severity_score,
                r.run_at                 AS run_timestamp
            FROM attack_prompts p
            LEFT JOIN attack_runs r ON r.prompt_id = p.id
            LEFT JOIN tools t ON p.target_tool_id = t.id
            ORDER BY r.severity_score DESC NULLS LAST
        """, conn)

    df["inferred_intent"] = df["prompt_text"].apply(classify_prompt_intent)
    df["inference_time_sec"] = None
    df["confidence"] = None
    df["label"] = df["inferred_intent"]  # fallback for label
    
    # if attack_category is null, use inferred_intent for filtering
    df["attack_category"] = df["attack_category"].fillna(df["inferred_intent"])
    
    return df


# =========================
# HELPERS
# =========================

def severity_band(score):
    if score is None or pd.isna(score): return "unknown"
    if score >= 0.9:   return "critical"
    if score >= 0.7:   return "high"
    if score >= 0.5:   return "medium"
    if score >= 0.3:   return "low"
    return "none"

def severity_color(band):
    return {
        "critical": "#ff4444", "high": "#ff9944",
        "medium":   "#ffdd44", "low":  "#44ff88",
        "none":     "#6e6e9e", "unknown": "#444466"
    }.get(band, "#6e6e9e")

def severity_emoji(band):
    return {
        "critical": "🔴", "high": "🟠",
        "medium":   "🟡", "low":  "🟢",
        "none":     "⚪", "unknown": "⚫"
    }.get(band, "⚫")

TOOL_ATTACK_CATEGORIES = [
    "database_query", "file_system", "code_execution", "web_request",
    "email_messaging", "credential_theft", "memory_manipulation",
    "system_access", "data_exfiltration", "privilege_escalation"
]


# =========================
# LOAD & PREP DATA
# =========================

df = load_data()
df["severity_band"] = df["severity_score"].apply(severity_band)
df["success_label"] = df["success_flag"].map({True: "SUCCESS", False: "FAILED", None: "UNKNOWN"})
df["is_tool_attack"] = df["attack_category"].isin(TOOL_ATTACK_CATEGORIES)


# =========================
# SIDEBAR FILTERS
# =========================

st.sidebar.markdown("## 🛠️ Tool Abuse Analytics")
st.sidebar.markdown("---")

# Search
search = st.sidebar.text_input("🔍 Search prompts / responses", placeholder="keyword...")

# Success filter
success_filter = st.sidebar.multiselect(
    "Result",
    options=["SUCCESS", "FAILED", "UNKNOWN"],
    default=["SUCCESS", "FAILED", "UNKNOWN"]
)

# Category filter
all_cats = sorted(df["attack_category"].dropna().unique().tolist())
cat_filter = st.sidebar.multiselect("Attack Category", options=all_cats, default=[])

# Severity filter
sev_filter = st.sidebar.multiselect(
    "Severity Band",
    options=["critical", "high", "medium", "low", "none", "unknown"],
    default=[]
)

# Score range
min_score, max_score = st.sidebar.slider(
    "Severity Score Range",
    min_value=0.0, max_value=1.0,
    value=(0.0, 1.0), step=0.05
)

# Technique filter
all_techs = sorted(df["attack_technique"].dropna().unique().tolist())
tech_filter = st.sidebar.multiselect("Attack Technique", options=all_techs, default=[])

# Tool call type filter
all_tool_types = sorted(df["tool_call_type"].dropna().unique().tolist())
tool_type_filter = st.sidebar.multiselect("Tool Call Type", options=all_tool_types, default=[])

# Sort
sort_by = st.sidebar.selectbox(
    "Sort By",
    options=["severity_score", "inference_time_sec", "confidence", "run_timestamp"],
    index=0
)
sort_asc = st.sidebar.checkbox("Ascending", value=False)

# Rows per page
page_size = st.sidebar.selectbox("Rows per page", [25, 50, 100, 200], index=1)

st.sidebar.markdown("---")
if st.sidebar.button("🔄 Refresh Data"):
    st.cache_data.clear()
    st.rerun()


# =========================
# APPLY FILTERS
# =========================

filtered = df.copy()

if search:
    mask = (
        filtered["prompt_text"].str.contains(search, case=False, na=False) |
        filtered["llm_output"].str.contains(search, case=False, na=False) |
        filtered["attack_category"].str.contains(search, case=False, na=False)
    )
    filtered = filtered[mask]

if success_filter:
    filtered = filtered[filtered["success_label"].isin(success_filter)]

if cat_filter:
    filtered = filtered[filtered["attack_category"].isin(cat_filter)]

if sev_filter:
    filtered = filtered[filtered["severity_band"].isin(sev_filter)]

if tech_filter:
    filtered = filtered[filtered["attack_technique"].isin(tech_filter)]

if tool_type_filter:
    filtered = filtered[filtered["tool_call_type"].isin(tool_type_filter)]

filtered = filtered[
    (filtered["severity_score"].isna()) |
    ((filtered["severity_score"] >= min_score) & (filtered["severity_score"] <= max_score))
]

filtered = filtered.sort_values(sort_by, ascending=sort_asc, na_position="last")


# =========================
# TITLE
# =========================

st.markdown("""
<div class="title-bar">
    <h1 style="margin:0; padding:0;">🛠️ Tool Abuse Intelligence Dashboard</h1>
    <p style="color:#6e6e9e; font-family:'JetBrains Mono',monospace; font-size:12px; margin:4px 0 0 0;">
        Prompt Injection Red Teaming · Tool Abuse Analysis · Attack Vector Mapping · Vulnerability Assessment
    </p>
</div>
""", unsafe_allow_html=True)


# =========================
# TOP METRICS
# =========================

total          = len(df)
evaluated      = int(df["success_flag"].notna().sum())
successes      = int(df["success_flag"].sum()) if df["success_flag"].notna().any() else 0
success_rate   = round(successes / evaluated * 100, 1) if evaluated > 0 else 0
critical       = int((df["severity_band"] == "critical").sum())
high           = int((df["severity_band"] == "high").sum())
avg_score      = round(df["severity_score"].mean(), 3) if df["severity_score"].notna().any() else 0
tool_attacks   = int(df["is_tool_attack"].sum())

c1, c2, c3, c4, c5, c6, c7 = st.columns(7)
c1.metric("Total Prompts",      f"{total:,}")
c2.metric("Evaluated",          f"{evaluated:,}")
c3.metric("Successful Attacks", f"{successes:,}")
c4.metric("Success Rate",       f"{success_rate}%")
c5.metric("Critical",           f"{critical:,}")
c6.metric("High Severity",      f"{high:,}")
c7.metric("Tool Abuse Hits",    f"{tool_attacks:,}")

st.markdown("---")


# =========================
# TABS
# =========================

tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Overview Analytics",
    "🛠️ Tool Abuse Deep Dive",
    "📋 Prompt Browser",
    "🔬 Detail View"
])


# =========================================================
# TAB 1: OVERVIEW ANALYTICS
# =========================================================

with tab1:
    col1, col2 = st.columns(2)

    # --- Attack Category Breakdown ---
    with col1:
        st.markdown("### Attack Category Breakdown")
        cat_counts = df[df["success_flag"] == True]["attack_category"].value_counts().reset_index()
        cat_counts.columns = ["category", "count"]
        if not cat_counts.empty:
            fig = px.bar(
                cat_counts, x="count", y="category", orientation="h",
                color="count",
                color_continuous_scale=["#1a0a2e", "#7c3aed", "#e040fb"],
                template="plotly_dark"
            )
            fig.update_layout(**CHART_LAYOUT, height=380, showlegend=False, coloraxis_showscale=False)
            fig.update_xaxes(gridcolor=GRID_COLOR)
            fig.update_yaxes(gridcolor=GRID_COLOR)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No successful attacks to display.")

    # --- Severity Distribution (Donut) ---
    with col2:
        st.markdown("### Severity Distribution")
        sev_counts = df["severity_band"].value_counts().reset_index()
        sev_counts.columns = ["band", "count"]
        color_map = {
            "critical": "#ff4444", "high": "#ff9944",
            "medium": "#ffdd44", "low": "#44ff88",
            "none": "#6e6e9e", "unknown": "#444466"
        }
        if not sev_counts.empty:
            fig2 = px.pie(
                sev_counts, names="band", values="count",
                color="band", color_discrete_map=color_map,
                hole=0.5, template="plotly_dark"
            )
            fig2.update_layout(**CHART_LAYOUT, height=380)
            st.plotly_chart(fig2, use_container_width=True)

    col3, col4 = st.columns(2)

    # --- Attack Technique vs Success Rate ---
    with col3:
        st.markdown("### Attack Technique vs Success Rate")
        tech_df = df[df["attack_technique"].notna()].groupby("attack_technique").agg(
            total=("success_flag", "count"),
            succeeded=("success_flag", "sum")
        ).reset_index()
        tech_df["success_rate"] = (tech_df["succeeded"] / tech_df["total"] * 100).round(1)
        tech_df = tech_df.sort_values("success_rate", ascending=False)

        if not tech_df.empty:
            fig3 = px.bar(
                tech_df, x="attack_technique", y="success_rate",
                color="success_rate",
                color_continuous_scale=["#1e1e3a", "#7c3aed", "#ff4444"],
                template="plotly_dark", text="success_rate"
            )
            fig3.update_traces(texttemplate="%{text:.1f}%", textposition="outside")
            fig3.update_layout(**CHART_LAYOUT, height=360, showlegend=False, coloraxis_showscale=False)
            fig3.update_xaxes(gridcolor=GRID_COLOR)
            fig3.update_yaxes(gridcolor=GRID_COLOR)
            st.plotly_chart(fig3, use_container_width=True)
        else:
            st.info("No technique data available.")

    # --- Severity Score Histogram ---
    with col4:
        st.markdown("### Severity Score Distribution")
        scored = df[df["severity_score"].notna()]
        if not scored.empty:
            fig4 = px.histogram(
                scored, x="severity_score", nbins=20,
                color_discrete_sequence=["#7c3aed"],
                template="plotly_dark"
            )
            fig4.update_layout(**CHART_LAYOUT, height=360, bargap=0.1)
            fig4.update_xaxes(gridcolor=GRID_COLOR)
            fig4.update_yaxes(gridcolor=GRID_COLOR)
            st.plotly_chart(fig4, use_container_width=True)

    col5, col6 = st.columns(2)

    # --- Success vs Failure Pie ---
    with col5:
        st.markdown("### Success vs Failure")
        result_counts = df["success_label"].value_counts().reset_index()
        result_counts.columns = ["result", "count"]
        result_color_map = {
            "SUCCESS": "#22c55e", "FAILED": "#ef4444", "UNKNOWN": "#6e6e9e"
        }
        if not result_counts.empty:
            fig5 = px.pie(
                result_counts, names="result", values="count",
                color="result", color_discrete_map=result_color_map,
                hole=0.45, template="plotly_dark"
            )
            fig5.update_layout(**CHART_LAYOUT, height=340)
            st.plotly_chart(fig5, use_container_width=True)

    # --- Tool Call Type Distribution ---
    with col6:
        st.markdown("### Tool Call Type Distribution")
        tool_counts = df[df["tool_call_type"].notna() & (df["tool_call_type"] != "none")]
        tool_counts = tool_counts["tool_call_type"].value_counts().reset_index()
        tool_counts.columns = ["tool_type", "count"]
        if not tool_counts.empty:
            fig6 = px.bar(
                tool_counts, x="tool_type", y="count",
                color="count",
                color_continuous_scale=["#0f0f1a", "#06b6d4", "#e040fb"],
                template="plotly_dark", text="count"
            )
            fig6.update_traces(textposition="outside")
            fig6.update_layout(**CHART_LAYOUT, height=340, showlegend=False, coloraxis_showscale=False)
            fig6.update_xaxes(gridcolor=GRID_COLOR)
            fig6.update_yaxes(gridcolor=GRID_COLOR)
            st.plotly_chart(fig6, use_container_width=True)
        else:
            st.info("No tool call data available.")


# =========================================================
# TAB 2: TOOL ABUSE DEEP DIVE
# =========================================================

with tab2:
    tool_df = df[df["is_tool_attack"]].copy()

    st.markdown(f"### 🛠️ Tool Abuse Attacks — {len(tool_df):,} total")

    if tool_df.empty:
        st.warning("No tool abuse attacks found in the dataset.")
    else:
        # KPI row for tool attacks
        tc1, tc2, tc3, tc4, tc5 = st.columns(5)
        tool_success  = int(tool_df["success_flag"].sum()) if tool_df["success_flag"].notna().any() else 0
        tool_eval     = int(tool_df["success_flag"].notna().sum())
        tool_rate     = round(tool_success / tool_eval * 100, 1) if tool_eval > 0 else 0
        tool_critical = int((tool_df["severity_band"] == "critical").sum())
        tool_avg      = round(tool_df["severity_score"].mean(), 3) if tool_df["severity_score"].notna().any() else 0

        tc1.metric("Tool Attacks", f"{len(tool_df):,}")
        tc2.metric("Successful",   f"{tool_success:,}")
        tc3.metric("Success Rate", f"{tool_rate}%")
        tc4.metric("Critical",     f"{tool_critical:,}")
        tc5.metric("Avg Severity", f"{tool_avg}")

        st.markdown("---")

        tcol1, tcol2 = st.columns(2)

        # --- Tool Attack Category Breakdown ---
        with tcol1:
            st.markdown("### Tool Attack Categories")
            tcat_counts = tool_df["attack_category"].value_counts().reset_index()
            tcat_counts.columns = ["category", "count"]
            fig_t1 = px.bar(
                tcat_counts, x="count", y="category", orientation="h",
                color="category",
                color_discrete_sequence=["#e040fb", "#7c3aed", "#06b6d4", "#f59e0b", "#ef4444"],
                template="plotly_dark", text="count"
            )
            fig_t1.update_traces(textposition="outside")
            fig_t1.update_layout(**CHART_LAYOUT, height=320, showlegend=False)
            fig_t1.update_xaxes(gridcolor=GRID_COLOR)
            fig_t1.update_yaxes(gridcolor=GRID_COLOR)
            st.plotly_chart(fig_t1, use_container_width=True)

        # --- Tool Call Type Breakdown within tool attacks ---
        with tcol2:
            st.markdown("### Tool Call Types (within tool attacks)")
            tt_counts = tool_df[tool_df["tool_call_type"].notna() & (tool_df["tool_call_type"] != "none")]
            tt_counts = tt_counts["tool_call_type"].value_counts().reset_index()
            tt_counts.columns = ["type", "count"]
            if not tt_counts.empty:
                fig_t2 = px.pie(
                    tt_counts, names="type", values="count",
                    color_discrete_sequence=CHART_COLORS,
                    hole=0.45, template="plotly_dark"
                )
                fig_t2.update_layout(**CHART_LAYOUT, height=320)
                st.plotly_chart(fig_t2, use_container_width=True)
            else:
                st.info("No tool call type data.")

        tcol3, tcol4 = st.columns(2)

        # --- Tool Attacks by Severity Band ---
        with tcol3:
            st.markdown("### Tool Attacks by Severity Band")
            tsev = tool_df["severity_band"].value_counts().reset_index()
            tsev.columns = ["band", "count"]
            sev_order = ["critical", "high", "medium", "low", "none", "unknown"]
            tsev["band"] = pd.Categorical(tsev["band"], categories=sev_order, ordered=True)
            tsev = tsev.sort_values("band")
            sev_color_map = {
                "critical": "#ff4444", "high": "#ff9944",
                "medium": "#ffdd44", "low": "#44ff88",
                "none": "#6e6e9e", "unknown": "#444466"
            }
            fig_t3 = px.bar(
                tsev, x="band", y="count",
                color="band", color_discrete_map=sev_color_map,
                template="plotly_dark", text="count"
            )
            fig_t3.update_traces(textposition="outside")
            fig_t3.update_layout(**CHART_LAYOUT, height=320, showlegend=False)
            fig_t3.update_xaxes(gridcolor=GRID_COLOR)
            fig_t3.update_yaxes(gridcolor=GRID_COLOR)
            st.plotly_chart(fig_t3, use_container_width=True)

        # --- Tool Attack Technique Breakdown ---
        with tcol4:
            st.markdown("### Tool Attack Techniques")
            ttech = tool_df[tool_df["attack_technique"].notna()]
            ttech = ttech["attack_technique"].value_counts().reset_index()
            ttech.columns = ["technique", "count"]
            if not ttech.empty:
                fig_t4 = px.bar(
                    ttech, x="technique", y="count",
                    color="count",
                    color_continuous_scale=["#1a0a2e", "#06b6d4", "#e040fb"],
                    template="plotly_dark", text="count"
                )
                fig_t4.update_traces(textposition="outside")
                fig_t4.update_layout(**CHART_LAYOUT, height=320, showlegend=False, coloraxis_showscale=False)
                fig_t4.update_xaxes(gridcolor=GRID_COLOR)
                fig_t4.update_yaxes(gridcolor=GRID_COLOR)
                st.plotly_chart(fig_t4, use_container_width=True)
            else:
                st.info("No technique data for tool attacks.")

        # --- Top 10 Highest Severity Tool Abuse Prompts ---
        st.markdown("### ⚠️ Top 10 Highest Severity Tool Abuse Prompts")
        top_tool = tool_df.dropna(subset=["severity_score"]).nlargest(10, "severity_score")

        for _, row in top_tool.iterrows():
            band  = row["severity_band"]
            score = row["severity_score"]
            cat   = row["attack_category"] or "unknown"
            tech  = row["attack_technique"] or "unknown"
            tool  = row["tool_call_type"] or "none"
            result = row["success_label"]

            score_display = f"{score:.2f}" if pd.notna(score) else "N/A"
            emoji = severity_emoji(band)

            label = f"{emoji}  [{score_display}]  {cat}  ·  tool={tool}  ·  {result}"

            with st.expander(label):
                ec1, ec2, ec3, ec4 = st.columns(4)
                ec1.markdown(f"**Severity**<br>`{score_display}`", unsafe_allow_html=True)
                ec2.markdown(f"**Category**<br>`{cat}`", unsafe_allow_html=True)
                ec3.markdown(f"**Tool Type**<br>`{tool}`", unsafe_allow_html=True)
                ec4.markdown(f"**Technique**<br>`{tech}`", unsafe_allow_html=True)

                st.markdown("**Attack Prompt:**")
                st.code(str(row["prompt_text"]), language=None)

                st.markdown("**Model Response:**")
                st.code(str(row["llm_output"]) if pd.notna(row["llm_output"]) else "No response", language=None)


# =========================================================
# TAB 3: PROMPT BROWSER
# =========================================================

with tab3:
    st.markdown(f"### Showing {len(filtered):,} of {total:,} prompts")

    # Pagination
    total_pages = max(1, (len(filtered) - 1) // page_size + 1)
    page = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1, key="browser_page")
    start = (page - 1) * page_size
    end = start + page_size
    page_df = filtered.iloc[start:end]

    # Table view
    display_cols = ["prompt_text", "attack_category", "severity_score",
                    "severity_band", "success_label", "attack_technique",
                    "tool_call_type", "confidence", "inference_time_sec", "model_name"]

    show_df = page_df[display_cols].copy()
    show_df["prompt_text"] = show_df["prompt_text"].str[:80] + "..."
    show_df["severity_score"] = pd.to_numeric(show_df["severity_score"], errors="coerce").round(3)
    show_df["confidence"]     = pd.to_numeric(show_df["confidence"], errors="coerce").round(3)
    show_df["inference_time_sec"] = pd.to_numeric(show_df["inference_time_sec"], errors="coerce").round(2)

    st.dataframe(
        show_df,
        use_container_width=True,
        height=450,
        column_config={
            "prompt_text":        st.column_config.TextColumn("Prompt", width="large"),
            "attack_category":    st.column_config.TextColumn("Category", width="medium"),
            "severity_score":     st.column_config.ProgressColumn("Severity", min_value=0, max_value=1, width="small"),
            "severity_band":      st.column_config.TextColumn("Band", width="small"),
            "success_label":      st.column_config.TextColumn("Result", width="small"),
            "attack_technique":   st.column_config.TextColumn("Technique", width="small"),
            "tool_call_type":     st.column_config.TextColumn("Tool Type", width="small"),
            "confidence":         st.column_config.ProgressColumn("Confidence", min_value=0, max_value=1, width="small"),
            "inference_time_sec": st.column_config.NumberColumn("Time(s)", width="small"),
            "model_name":         st.column_config.TextColumn("Model", width="small"),
        }
    )

    st.markdown(f"*Page {page} of {total_pages} · {len(filtered):,} results*")

    # Download
    st.download_button(
        label="⬇️ Download filtered results as CSV",
        data=filtered.to_csv(index=False).encode("utf-8"),
        file_name="tool_abuse_filtered.csv",
        mime="text/csv"
    )


# =========================================================
# TAB 4: DETAIL VIEW
# =========================================================

with tab4:
    st.markdown("### Full Prompt + Response Detail View")
    st.markdown("Expand any row to see the full prompt and model response.")

    detail_df = filtered.iloc[:100]

    for _, row in detail_df.iterrows():
        band   = row["severity_band"]
        score  = row["severity_score"]
        cat    = row["attack_category"] or "unknown"
        tech   = row["attack_technique"] or "unknown"
        tool   = row["tool_call_type"] or "none"
        result = row["success_label"]
        conf   = row["confidence"]
        itime  = row["inference_time_sec"]

        score_display = f"{score:.2f}" if pd.notna(score) else "N/A"
        conf_display  = f"{conf:.2f}"  if pd.notna(conf)  else "N/A"
        time_display  = f"{itime:.2f}s" if pd.notna(itime) else "N/A"
        emoji = severity_emoji(band)

        label = (
            f"{emoji}  [{score_display}]  {cat}  ·  {tech}  ·  tool={tool}  ·  {result}"
        )

        with st.expander(label):
            dc1, dc2, dc3, dc4, dc5 = st.columns(5)
            dc1.markdown(f"**Severity**<br>`{score_display}`", unsafe_allow_html=True)
            dc2.markdown(f"**Band**<br>`{band}`", unsafe_allow_html=True)
            dc3.markdown(f"**Confidence**<br>`{conf_display}`", unsafe_allow_html=True)
            dc4.markdown(f"**Tool Type**<br>`{tool}`", unsafe_allow_html=True)
            dc5.markdown(f"**Inference**<br>`{time_display}`", unsafe_allow_html=True)

            st.markdown("**Attack Prompt:**")
            st.code(str(row["prompt_text"]), language=None)

            st.markdown("**Model Response:**")
            st.code(str(row["llm_output"]) if pd.notna(row["llm_output"]) else "No response", language=None)


# =========================
# FOOTER
# =========================

st.markdown("---")
st.markdown(
    '<p style="text-align:center; color:#3a3a5e; font-family:JetBrains Mono,monospace; font-size:11px;">'
    '🛠️ Tool Abuse Intelligence Dashboard · Prompt Injection Red Teaming · v3.0'
    '</p>',
    unsafe_allow_html=True
)
