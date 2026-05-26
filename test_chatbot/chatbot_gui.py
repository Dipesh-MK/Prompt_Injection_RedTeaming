import streamlit as st
import requests
import json
import uuid

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SecureBank AI",
    page_icon="🏦",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Custom CSS for Banking Theme ─────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');



/* ── Top Bar ── */
.top-bar {
    background: #003366;
    color: white;
    padding: 1rem 2rem;
    border-radius: 8px;
    margin-bottom: 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}
.bank-logo {
    font-size: 1.5rem;
    font-weight: 700;
    display: flex;
    align-items: center;
    gap: 10px;
}
.user-status {
    font-size: 0.9rem;
    font-weight: 500;
}

/* ── Tool Sidebar ── */
[data-testid="stSidebar"] {
    background: #ffffff !important;
    border-right: 1px solid #e0e0e0;
}
.tool-header {
    font-size: 1.1rem;
    font-weight: 600;
    color: #003366;
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 2px solid #f0f0f0;
}
.tool-card {
    background: #f9fbfb;
    border: 1px solid #e5e9ea;
    border-radius: 8px;
    padding: 12px;
    margin-bottom: 10px;
    font-size: 0.85rem;
}
.tool-name {
    font-weight: 700;
    color: #0088cc;
    margin-bottom: 4px;
}
.tool-status {
    color: #28a745;
    font-size: 0.75rem;
    font-weight: 600;
}
.tool-status.error {
    color: #dc3545;
}

/* ── Chat Messages ── */
.chat-bubble-user {
    background: #0088cc;
    color: white;
    padding: 10px 15px;
    border-radius: 12px 12px 0 12px;
    margin-bottom: 10px;
    display: inline-block;
    max-width: 80%;
}
.chat-bubble-ai {
    background: #ffffff;
    color: #333333;
    border: 1px solid #e0e0e0;
    padding: 10px 15px;
    border-radius: 12px 12px 12px 0;
    margin-bottom: 10px;
    display: inline-block;
    max-width: 80%;
    box-shadow: 0 2px 4px rgba(0,0,0,0.05);
}
</style>
""", unsafe_allow_html=True)


# ── Initialization ───────────────────────────────────────────────────────────
if "session_id" not in st.session_state:
    st.session_state.session_id = f"gui-sess-{uuid.uuid4().hex[:8]}"

if "messages" not in st.session_state:
    st.session_state.messages = []

if "tool_history" not in st.session_state:
    st.session_state.tool_history = []


# ── UI Structure ─────────────────────────────────────────────────────────────
st.markdown("""
<div class="top-bar">
    <div class="bank-logo">🏦 SecureBank Corp</div>
    <div class="user-status">🟢 System Online</div>
</div>
""", unsafe_allow_html=True)


# ── Sidebar (Simulated Tool Monitoring) ──────────────────────────────────────
with st.sidebar:
    st.markdown('<div class="tool-header">⚡ Backend Execution Trace</div>', unsafe_allow_html=True)
    if st.button("🔄 Reset Session", use_container_width=True):
        st.session_state.messages = []
        st.session_state.tool_history = []
        try:
            requests.post("http://localhost:5050/reset", json={"session_id": st.session_state.session_id}, timeout=3)
        except:
            pass
        st.rerun()
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    if st.session_state.tool_history:
        for tool in reversed(st.session_state.tool_history[-10:]):
            status_class = "error" if tool['result'].get('status') == 'error' else ""
            status_text = tool['result'].get('status', 'executed').upper()
            st.markdown(f"""
            <div class="tool-card">
                <div class="tool-name">🔧 {tool['tool_name']}</div>
                <div style="margin-bottom: 4px; color: #555;">Args: <code>{json.dumps(tool['arguments'])}</code></div>
                <div class="tool-status {status_class}">{status_text}</div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.caption("No tools have been executed in this session yet.")


# ── Chat Area ────────────────────────────────────────────────────────────────
chat_container = st.container()

with chat_container:
    # Display hello message from bot as initial
    if not st.session_state.messages:
        with st.chat_message("assistant", avatar="🏦"):
            st.write("Welcome to SecureBank Corp! How can I assist you with your banking needs today?")

    for msg in st.session_state.messages:
        if msg["role"] == "user":
            with st.chat_message("user", avatar="👤"):
                st.write(msg["content"])
        else:
            with st.chat_message("assistant", avatar="🏦"):
                st.write(msg["content"])


# ── Input Area ───────────────────────────────────────────────────────────────
prompt = st.chat_input("Ask SecureBank AI (e.g. What is my balance?)")

if prompt:
    # Append user msg to state
    st.session_state.messages.append({"role": "user", "content": prompt})
    
    # Render user msg immediately
    with chat_container:
        with st.chat_message("user", avatar="👤"):
            st.write(prompt)
            
    # Send request to local banking chatbot API
    backend_url = "http://localhost:5050/chat"
    payload = {
        "message": prompt,
        "session_id": st.session_state.session_id
    }
    
    with chat_container:
        with st.chat_message("assistant", avatar="🏦"):
            with st.spinner("Processing your request..."):
                try:
                    response = requests.post(backend_url, json=payload, timeout=300)
                    if response.status_code == 200:
                        data = response.json()
                        bot_reply = data.get("response", "Error reading response")
                        tools = data.get("tool_calls", [])
                        
                        st.write(bot_reply)
                        
                        st.session_state.messages.append({"role": "assistant", "content": bot_reply})
                        for t in tools:
                            st.session_state.tool_history.append(t)
                        
                        st.rerun() # Only rerun on success so sidebar updates
                    else:
                        st.error(f"Backend Server Error: {response.text}")
                except Exception as e:
                    st.error(f"Failed to connect to SecureBank backend API at {backend_url}. Error: {e}")
                    # Remove the user's message so they can try again if there's a timeout
                    if len(st.session_state.messages) > 0 and st.session_state.messages[-1]["role"] == "user":
                        st.session_state.messages.pop()
