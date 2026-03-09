# ============================================================
# SENTINEL-AI — Prompt Firewall
# Main Application File
# Connects all three gates into one working pipeline
# UI built with Streamlit
# ============================================================

import streamlit as st
from dotenv import load_dotenv
import os
import json
from datetime import datetime
from litellm import completion

# ── Load API keys from .env file ───────────────────────────
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# ── Import all three gates ─────────────────────────────────
from gates.gate1_pii import scan_pii
from gates.gate2_semantic import scan_semantics
from gates.gate3_output import scan_output

# ── Page configuration ─────────────────────────────────────
st.set_page_config(
    page_title="Sentinel-AI",
    page_icon="🛡️",
    layout="wide"
)

# ── Custom CSS for professional look ───────────────────────
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .block-container { padding-top: 2rem; }
    .stAlert { border-radius: 10px; }
    .metric-card {
        background-color: #1e2130;
        padding: 15px;
        border-radius: 10px;
        margin: 5px 0;
    }
    .gate-active {
        color: #00ff88;
        font-weight: bold;
    }
    .gate-blocked {
        color: #ff4444;
        font-weight: bold;
    }
    </style>
""", unsafe_allow_html=True)

# ── Initialize session state ───────────────────────────────
# Session state keeps data alive between interactions
# Without this counters reset every time user types
if "messages" not in st.session_state:
    st.session_state.messages = []
if "total_scanned" not in st.session_state:
    st.session_state.total_scanned = 0
if "total_blocked" not in st.session_state:
    st.session_state.total_blocked = 0
if "last_threat" not in st.session_state:
    st.session_state.last_threat = "None detected yet"
if "gate1_status" not in st.session_state:
    st.session_state.gate1_status = "✅ Active"
if "gate2_status" not in st.session_state:
    st.session_state.gate2_status = "✅ Active"
if "gate3_status" not in st.session_state:
    st.session_state.gate3_status = "✅ Active"


def call_llm(prompt: str) -> str:
    """
    Sends cleaned prompt to Llama 3 via LiteLLM + Groq.
    Returns the LLM response as a string.

    Args:
        prompt (str): The cleaned safe prompt

    Returns:
        str: The LLM response
    """
    try:
        response = completion(
            model="groq/llama-3.1-8b-instant",
            messages=[{"role": "user", "content": prompt}],
            api_key=GROQ_API_KEY
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"LLM Error: {str(e)}"


def run_pipeline(user_prompt: str) -> dict:
    """
    Runs the full three gate security pipeline.
    Gate 1 → Gate 2 → LLM → Gate 3

    Args:
        user_prompt (str): Raw user input

    Returns:
        dict: Results from all gates and final response
    """

    results = {
        "original_prompt": user_prompt,
        "cleaned_prompt": user_prompt,
        "pii_found": [],
        "gate2_blocked": False,
        "gate2_score": 0.0,
        "gate2_label": "",
        "llm_response": "",
        "gate3_safe": True,
        "gate3_toxic_score": 0.0,
        "gate3_leaked": False,
        "final_status": "safe"
    }

    # ── GATE 1 — PII Sanitization ──────────────────────────
    cleaned_prompt, pii_found = scan_pii(user_prompt)
    results["cleaned_prompt"] = cleaned_prompt
    results["pii_found"] = pii_found

    # ── GATE 2 — Injection Detection ──────────────────────
    is_blocked, score, label = scan_semantics(cleaned_prompt)
    results["gate2_blocked"] = is_blocked
    results["gate2_score"] = score
    results["gate2_label"] = label

    if is_blocked:
        results["final_status"] = "blocked_injection"
        return results

    # ── LLM Call — Only if Gate 2 allows ──────────────────
    llm_response = call_llm(cleaned_prompt)
    results["llm_response"] = llm_response

    # ── GATE 3 — Output Safety Filter ─────────────────────
    is_safe, toxic_score, leaked = scan_output(llm_response)
    results["gate3_safe"] = is_safe
    results["gate3_toxic_score"] = toxic_score
    results["gate3_leaked"] = leaked

    if not is_safe:
        results["final_status"] = "blocked_output"
        return results

    results["final_status"] = "safe"
    return results


# ════════════════════════════════════════════════════════════
# SIDEBAR — Security Dashboard
# ════════════════════════════════════════════════════════════
with st.sidebar:
    st.title("🛡️ Security Dashboard")
    st.divider()

    # ── Live Metrics ───────────────────────────────────────
    st.subheader("📊 Session Metrics")
    col1, col2 = st.columns(2)
    with col1:
        st.metric(
            label="Prompts Scanned",
            value=st.session_state.total_scanned
        )
    with col2:
        st.metric(
            label="Prompts Blocked",
            value=st.session_state.total_blocked
        )

    st.divider()

    # ── Last Threat ────────────────────────────────────────
    st.subheader("🚨 Last Threat Detected")
    st.info(st.session_state.last_threat)

    st.divider()

    # ── Gate Status ────────────────────────────────────────
    st.subheader("🔒 Gate Status")
    st.success("Gate 1 — PII Sanitization ✅")
    st.success("Gate 2 — Injection Detection ✅")
    st.success("Gate 3 — Output Safety Filter ✅")

    st.divider()

    # ── Threat Log Viewer ──────────────────────────────────
    # ── Threat Log Viewer ──────────────────────────────────
    try:
        with open("logs/threats.json", "r") as f:
            threats = json.load(f)

        if threats:
            # ── All Time Statistics ────────────────────────
            st.subheader("📈 All Time Statistics")

            # Count total threats
            total_threats = len(threats)

            # Count each threat type
            threat_types = {}
            for t in threats:
                threat_type = t["threat_type"]
                threat_types[threat_type] = (
                    threat_types.get(threat_type, 0) + 1
                )

            # Find most common attack type
            most_common = max(
                threat_types,
                key=threat_types.get
            )
            most_common_count = threat_types[most_common]
            most_common_pct = (
                most_common_count / total_threats * 100
            )

            # Show total threats metric
            st.metric(
                label="Total Threats Logged",
                value=total_threats
            )

            # Show most common attack
            st.info(
                f"**Most Common Attack:**\n\n"
                f"{most_common}\n\n"
                f"{most_common_count} times "
                f"({most_common_pct:.0f}%)"
            )

            # Show breakdown of all threat types
            st.subheader("🎯 Attack Breakdown")
            for threat_type, count in sorted(
                threat_types.items(),
                key=lambda x: x[1],
                reverse=True
            ):
                percentage = count / total_threats * 100
                st.progress(
                    percentage / 100,
                    text=f"{threat_type}: "
                         f"{count} ({percentage:.0f}%)"
                )

            st.divider()

            # ── Recent Threats ─────────────────────────────
            st.subheader("📋 Recent Threats")
            for threat in reversed(threats[-5:]):
                st.warning(
                    f"🔴 {threat['threat_type']}\n\n"
                    f"Score: {threat['confidence_score']}\n\n"
                    f"Time: {threat['timestamp']}"
                )

        else:
            st.subheader("📋 Recent Threats")
            st.write("No threats logged yet.")

    except Exception:
        st.subheader("📋 Recent Threats")
        st.write("No threats logged yet.")


# ════════════════════════════════════════════════════════════
# MAIN CHAT AREA
# ════════════════════════════════════════════════════════════
st.title("🛡️ Sentinel-AI Prompt Firewall")
st.caption(
    "Every prompt is scanned through 3 security gates "
    "before reaching the LLM."
)
st.divider()

# ── Display chat history ───────────────────────────────────
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# ── Chat input ─────────────────────────────────────────────
if prompt := st.chat_input("Type your prompt here..."):

    # Show user message immediately
    with st.chat_message("user"):
        st.markdown(prompt)
    st.session_state.messages.append(
        {"role": "user", "content": prompt}
    )

    # ── Run the full security pipeline ────────────────────
    with st.spinner("🔍 Scanning through security gates..."):
        results = run_pipeline(prompt)

    # ── Update session counters ────────────────────────────
    st.session_state.total_scanned += 1

    # ── Display results based on pipeline outcome ──────────
    with st.chat_message("assistant"):

        # ── Show Gate 1 results if PII was found ──────────
        if results["pii_found"]:
            st.warning(
                f"🟡 **Gate 1 — PII Detected & Cleaned**\n\n"
                f"Found: `{', '.join(results['pii_found'])}`\n\n"
                f"Cleaned prompt sent to next gate."
            )

        # ── BLOCKED by Gate 2 ──────────────────────────────
        if results["final_status"] == "blocked_injection":
            st.session_state.total_blocked += 1
            st.session_state.last_threat = (
                f"Prompt Injection "
                f"({results['gate2_score']*100:.1f}% confidence)"
            )
            st.error(
                f"🔴 **PROMPT BLOCKED — Gate 2**\n\n"
                f"**Reason:** Potential prompt injection detected\n\n"
                f"**Confidence:** "
                f"{results['gate2_score']*100:.1f}%\n\n"
                f"**Tip:** Try rephrasing your prompt."
            )
            response_text = "⛔ Prompt blocked by security firewall."

        # ── BLOCKED by Gate 3 ──────────────────────────────
        elif results["final_status"] == "blocked_output":
            st.session_state.total_blocked += 1
            if results["gate3_leaked"]:
                reason = "Credential leak detected in response"
                st.session_state.last_threat = "Credential Leak in Output"
            else:
                reason = "Toxic content detected in response"
                st.session_state.last_threat = "Toxic Output"
            st.error(
                f"🔴 **RESPONSE BLOCKED — Gate 3**\n\n"
                f"**Reason:** {reason}\n\n"
                f"The LLM response was unsafe and has been "
                f"blocked for your protection."
            )
            response_text = "⛔ Response blocked by security firewall."

        # ── SAFE — deliver response ────────────────────────
        else:
            st.success(
                f"🟢 **All Gates Passed**\n\n"
                f"Prompt scanned and response verified safe."
            )
            response_text = results["llm_response"]
            st.markdown(response_text)

        # Save response to chat history
        st.session_state.messages.append(
            {"role": "assistant", "content": response_text}
        )