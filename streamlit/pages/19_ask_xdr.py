import streamlit as st
import json
from utils.deprecation import show_deprecation_banner

st.set_page_config(page_title="Ask XDR", layout="wide")
show_deprecation_banner("ask_xdr")
st.title("Ask XDR")
st.caption("Chat with your XDR - a Cortex Agent over the semantic view, alert search, entity investigation, and the attack graph")

conn = st.connection("snowflake")

if "messages" not in st.session_state:
    st.session_state.messages = []

EXAMPLES = [
    "How many high severity findings are there this week?",
    "What happened with the user jsmith?",
    "Trace the attack path from 10.1.5.107",
    "Which MITRE tactics have no detection coverage?",
    "Find alerts similar to SMB lateral movement",
]

for ex in EXAMPLES:
    if st.button(ex, key=f"ex_{hash(ex)}"):
        st.session_state.messages.append({"role": "user", "content": [{"type": "text", "text": ex}]})
        st.rerun()

# Render history
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        for part in msg["content"]:
            if part["type"] == "text":
                st.markdown(part["text"])

# Input
prompt = st.chat_input("Ask a security question...")
if prompt:
    st.session_state.messages.append({"role": "user", "content": [{"type": "text", "text": prompt}]})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        with st.spinner("XDR Analyst agent thinking..."):
            try:
                payload = json.dumps({"messages": st.session_state.messages})
                r = conn.query(
                    "SELECT SNOWFLAKE.CORTEX.DATA_AGENT_RUN("
                    "'SNOWFLAKE_XDR.DASHBOARDS.XDR_ANALYST', %s, TRUE) AS resp",
                    params=(payload,), ttl=0,
                )
                resp = json.loads(r.iloc[0][0])

                # Extract text parts of the assistant response
                texts = []
                for part in resp.get("content", []):
                    if part.get("type") == "text":
                        texts.append(part["text"])
                    elif part.get("type") == "tool_result":
                        # Skip tool internals - show only user-facing text
                        pass
                answer = "\n\n".join(texts) or "(no text response)"

                st.markdown(answer)
                st.session_state.messages.append(
                    {"role": "assistant", "content": [{"type": "text", "text": answer}]})
            except Exception as e:
                st.error(f"Agent call failed: {e}")
