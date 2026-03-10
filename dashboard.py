import streamlit as st
import pandas as pd
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool
import plotly.express as px
import plotly.graph_objects as go

# =========================
# CONFIG
# =========================

DB_URI = "postgresql://postgres:Aracknab420697!?@localhost:5432/redteam"

st.set_page_config(
    page_title="Red Team Dashboard",
    page_icon="🔴",
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

    /* Tag badges */
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

    /* Severity bar */
    .sev-bar-wrap {
        background: #1a1a2e;
        border-radius: 4px;
        height: 6px;
        width: 100%;
        margin-top: 4px;
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
</style>
""", unsafe_allow_html=True)


# =========================
# DB LOADER
# =========================

@st.cache_data(ttl=60)
def load_data():
    engine = create_engine(DB_URI, poolclass=NullPool)
    with engine.connect() as conn:
        df = pd.read_sql("""
            SELECT
                p.id            AS prompt_id,
                p.prompt_text,
                p.label,
                e.id            AS eval_id,
                e.llm_output,
                e.model_name,
                e.inference_time_sec,
                e.success_flag,
                e.leak_type     AS attack_category,
                e.severity_score,
                e.tool_call_type,
                e.attack_technique,
                e.confidence,
                e.evaluator_version,
                e.evaluation_timestamp,
                e.timestamp     AS run_timestamp
            FROM prompts p
            LEFT JOIN evaluated_prompts e ON e.prompt_id = p.id
            ORDER BY e.severity_score DESC NULLS LAST
        """, conn)
    return df


# =========================
# HELPERS
# =========================

def severity_band(score):
    if score is None:  return "unknown"
    if score >= 0.9:   return "critical"
    if score >= 0.7:   return "high"
    if score >= 0.5:   return "medium"
    if score >= 0.3:   return "low"
    return "none"

def severity_color(band):
    return {
        "critical": "#ff4444",
        "high":     "#ff9944",
        "medium":   "#ffdd44",
        "low":      "#44ff88",
        "none":     "#6e6e9e",
        "unknown":  "#444466"
    }.get(band, "#6e6e9e")

def badge(text, kind="category"):
    return f'<span class="badge badge-{kind}">{text}</span>'


# =========================
# LOAD DATA
# =========================

df = load_data()
df["severity_band"] = df["severity_score"].apply(severity_band)
df["success_label"] = df["success_flag"].map({True: "SUCCESS", False: "FAILED", None: "UNKNOWN"})

# =========================
# SIDEBAR FILTERS
# =========================

st.sidebar.markdown("## 🔴 Red Team")
st.sidebar.markdown("---")

# Search
search = st.sidebar.text_input("🔍 Search prompts", placeholder="keyword...")

# Success filter
success_filter = st.sidebar.multiselect(
    "Result",
    options=["SUCCESS", "FAILED", "UNKNOWN"],
    default=["SUCCESS", "FAILED", "UNKNOWN"]
)

# Category filter
all_cats = sorted(df["attack_category"].dropna().unique().tolist())
cat_filter = st.sidebar.multiselect(
    "Attack Category",
    options=all_cats,
    default=[]
)

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
tech_filter = st.sidebar.multiselect(
    "Attack Technique",
    options=all_techs,
    default=[]
)

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
    <h1 style="margin:0; padding:0;">🔴 Red Team Intelligence Dashboard</h1>
    <p style="color:#6e6e9e; font-family:'JetBrains Mono',monospace; font-size:12px; margin:4px 0 0 0;">
        LLM Security Testing · Attack Analysis · Vulnerability Mapping
    </p>
</div>
""", unsafe_allow_html=True)

# =========================
# TOP METRICS
# =========================

total        = len(df)
successes    = int(df["success_flag"].sum()) if df["success_flag"].notna().any() else 0
success_rate = round(successes / total * 100, 1) if total > 0 else 0
critical     = int((df["severity_band"] == "critical").sum())
high         = int((df["severity_band"] == "high").sum())
avg_score    = round(df["severity_score"].mean(), 3) if df["severity_score"].notna().any() else 0

c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("Total Prompts",   f"{total:,}")
c2.metric("Successful Attacks", f"{successes:,}")
c3.metric("Success Rate",    f"{success_rate}%")
c4.metric("Critical",        f"{critical:,}")
c5.metric("High Severity",   f"{high:,}")
c6.metric("Avg Score",       f"{avg_score}")

st.markdown("---")

# =========================
# CHARTS ROW
# =========================

tab1, tab2, tab3 = st.tabs(["📊 Analytics", "📋 Prompt Browser", "🔬 Detail View"])

with tab1:
    col1, col2 = st.columns(2)

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
            fig.update_layout(
                paper_bgcolor="#0a0a0f", plot_bgcolor="#0f0f1a",
                font=dict(family="JetBrains Mono", color="#c0c0e0"),
                showlegend=False, coloraxis_showscale=False,
                margin=dict(l=0, r=0, t=10, b=0),
                height=340
            )
            fig.update_xaxes(gridcolor="#1e1e3a")
            fig.update_yaxes(gridcolor="#1e1e3a")
            st.plotly_chart(fig, use_container_width=True)

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
            fig2.update_layout(
                paper_bgcolor="#0a0a0f", plot_bgcolor="#0f0f1a",
                font=dict(family="JetBrains Mono", color="#c0c0e0"),
                margin=dict(l=0, r=0, t=10, b=0),
                height=340,
                legend=dict(bgcolor="#0f0f1a", bordercolor="#1e1e3a")
            )
            st.plotly_chart(fig2, use_container_width=True)

    col3, col4 = st.columns(2)

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
            fig3.update_layout(
                paper_bgcolor="#0a0a0f", plot_bgcolor="#0f0f1a",
                font=dict(family="JetBrains Mono", color="#c0c0e0"),
                showlegend=False, coloraxis_showscale=False,
                margin=dict(l=0, r=0, t=30, b=0), height=320
            )
            fig3.update_xaxes(gridcolor="#1e1e3a")
            fig3.update_yaxes(gridcolor="#1e1e3a")
            st.plotly_chart(fig3, use_container_width=True)

    with col4:
        st.markdown("### Severity Score Distribution")
        scored = df[df["severity_score"].notna()]
        if not scored.empty:
            fig4 = px.histogram(
                scored, x="severity_score", nbins=20,
                color_discrete_sequence=["#7c3aed"],
                template="plotly_dark"
            )
            fig4.update_layout(
                paper_bgcolor="#0a0a0f", plot_bgcolor="#0f0f1a",
                font=dict(family="JetBrains Mono", color="#c0c0e0"),
                margin=dict(l=0, r=0, t=30, b=0), height=320,
                bargap=0.1
            )
            fig4.update_xaxes(gridcolor="#1e1e3a")
            fig4.update_yaxes(gridcolor="#1e1e3a")
            st.plotly_chart(fig4, use_container_width=True)

# =========================
# PROMPT BROWSER TAB
# =========================

with tab2:
    st.markdown(f"### Showing {len(filtered):,} of {total:,} prompts")

    # Pagination
    total_pages = max(1, (len(filtered) - 1) // page_size + 1)
    page = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1)
    start = (page - 1) * page_size
    end   = start + page_size
    page_df = filtered.iloc[start:end]

    # Table view
    display_cols = ["prompt_text", "attack_category", "severity_score",
                    "severity_band", "success_label", "attack_technique",
                    "tool_call_type", "confidence", "inference_time_sec", "model_name"]

    show_df = page_df[display_cols].copy()
    show_df["prompt_text"] = show_df["prompt_text"].str[:80] + "..."
    show_df["severity_score"] = show_df["severity_score"].round(3)
    show_df["confidence"]     = show_df["confidence"].round(3)
    show_df["inference_time_sec"] = show_df["inference_time_sec"].round(2)

    st.dataframe(
        show_df,
        use_container_width=True,
        height=400,
        column_config={
            "prompt_text":        st.column_config.TextColumn("Prompt", width="large"),
            "attack_category":    st.column_config.TextColumn("Category", width="medium"),
            "severity_score":     st.column_config.ProgressColumn("Severity", min_value=0, max_value=1, width="small"),
            "severity_band":      st.column_config.TextColumn("Band", width="small"),
            "success_label":      st.column_config.TextColumn("Result", width="small"),
            "attack_technique":   st.column_config.TextColumn("Technique", width="small"),
            "tool_call_type":     st.column_config.TextColumn("Tool", width="small"),
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
        file_name="redteam_filtered.csv",
        mime="text/csv"
    )

# =========================
# DETAIL VIEW TAB
# =========================

with tab3:
    st.markdown("### Full Prompt + Response Detail View")
    st.markdown("Expand any row to see the full prompt and model response.")

    detail_df = filtered.iloc[:100]  # show top 100 in detail view

    for _, row in detail_df.iterrows():
        band  = row["severity_band"]
        score = row["severity_score"]
        cat   = row["attack_category"] or "unknown"
        tech  = row["attack_technique"] or "unknown"
        tool  = row["tool_call_type"] or "none"
        result= row["success_label"]
        conf  = row["confidence"]
        itime = row["inference_time_sec"]

        score_display = f"{score:.2f}" if score is not None else "N/A"
        conf_display  = f"{conf:.2f}"  if conf  is not None else "N/A"
        time_display  = f"{itime:.2f}s" if itime is not None else "N/A"

        label = (
            f"{'🔴' if band=='critical' else '🟠' if band=='high' else '🟡' if band=='medium' else '🟢' if band=='low' else '⚪'}  "
            f"[{score_display}]  {cat}  ·  {tech}  ·  {result}"
        )

        with st.expander(label):
            c1, c2, c3, c4, c5 = st.columns(5)
            c1.markdown(f"**Severity**<br>`{score_display}`", unsafe_allow_html=True)
            c2.markdown(f"**Band**<br>`{band}`", unsafe_allow_html=True)
            c3.markdown(f"**Confidence**<br>`{conf_display}`", unsafe_allow_html=True)
            c4.markdown(f"**Tool Intent**<br>`{tool}`", unsafe_allow_html=True)
            c5.markdown(f"**Inference**<br>`{time_display}`", unsafe_allow_html=True)

            st.markdown("**Attack Prompt:**")
            st.code(str(row["prompt_text"]), language=None)

            st.markdown("**Model Response:**")
            st.code(str(row["llm_output"]) if pd.notna(row["llm_output"]) else "No response", language=None)