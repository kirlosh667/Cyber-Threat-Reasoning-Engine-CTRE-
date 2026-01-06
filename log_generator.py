import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import time
import random

# =============================
# PAGE SETUP
# =============================
st.set_page_config(
    page_title="CTRE – Cyber Threat Reasoning Engine",
    layout="wide"
)

# =============================
# LIGHT PROFESSIONAL STYLING
# =============================
st.markdown("""
<style>
.block-container { padding-top: 1.5rem; }
h1 { font-size: 2.2rem; }
h2 { margin-top: 1.5rem; }
h3 { margin-top: 1rem; }
</style>
""", unsafe_allow_html=True)

# =============================
# TITLE
# =============================
st.title("CTRE – Cyber Threat Reasoning Engine")
st.caption(
    "CTRE allows users to simulate cyber attack scenarios, observe synthetic network traffic, "
    "and reason about threats like a system administrator."
)

# =============================
# SESSION STATE
# =============================
if "logs" not in st.session_state:
    st.session_state.logs = []

if "simulation_ran" not in st.session_state:
    st.session_state.simulation_ran = False

# =============================
# HELPER FUNCTIONS
# =============================
def highlight_attack_rows(row):
    if row["Status"] == "ATTACK":
        return ["background-color:#b30000;color:white;font-weight:bold"] * len(row)
    return [""] * len(row)

def risk_to_severity(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"

# ======================================================
# LEFT SIDEBAR — PROFESSIONAL CONTROL PANEL
# ======================================================
with st.sidebar:
    st.subheader("🧭 CTRE Control Panel")

    mode = st.radio(
        "Operation Mode",
        ["Scenario Controller", "Upload CSV"]
    )

    st.divider()
    st.caption("Controls only • Analysis on main screen")

# ======================================================
# MODE 1 — SCENARIO CONTROLLER (FEATURES UNCHANGED)
# ======================================================
if mode == "Scenario Controller":

    st.header("🎮 Attack Scenario Controller")

    attack_scenarios = st.multiselect(
        "Select Attack Scenarios",
        [
            "IoT Brute Force",
            "DNS Tunneling",
            "Web Application SQL Injection",
            "DDoS Traffic Flood",
            "Enterprise Breach (Multi-Vector Attack)"
        ]
    )

    scenario_scales = {}
    for scenario in attack_scenarios:
        scenario_scales[scenario] = st.slider(
            f"{scenario} – Attack Scale",
            1, 5, 2
        )

    attack_chains = {
        "IoT Brute Force": [
            "Device discovery",
            "SSH brute force",
            "Credential compromise",
            "Privilege escalation"
        ],
        "DNS Tunneling": [
            "Suspicious DNS queries",
            "Encoded payloads",
            "C2 communication"
        ],
        "Web Application SQL Injection": [
            "Injection probe",
            "SQL exploit",
            "Database access"
        ],
        "DDoS Traffic Flood": [
            "Traffic spike",
            "Service degradation",
            "Outage"
        ],
        "Enterprise Breach (Multi-Vector Attack)": [
            "Reconnaissance",
            "Initial access",
            "Command & Control",
            "Impact"
        ]
    }

    if st.button("🚀 Simulate Attacks"):
        st.session_state.logs = []
        base_time = datetime.now()

        for i in range(8):
            st.session_state.logs.append({
                "Time": base_time + timedelta(seconds=i * 3),
                "Scenario": "Baseline",
                "Activity": "Normal enterprise activity",
                "Status": "NORMAL"
            })

        for scenario in attack_scenarios:
            for i in range(len(attack_chains[scenario]) * scenario_scales[scenario]):
                st.session_state.logs.append({
                    "Time": base_time + timedelta(seconds=30 + i * 4),
                    "Scenario": scenario,
                    "Activity": attack_chains[scenario][i % len(attack_chains[scenario])],
                    "Status": "ATTACK"
                })

        st.session_state.logs.sort(key=lambda x: x["Time"])
        st.session_state.simulation_ran = True
        st.success("Simulation completed")

    if st.session_state.simulation_ran:
        df = pd.DataFrame(st.session_state.logs)

        st.header("📄 Simulated Network Activity")

        view = st.radio(
            "View Mode",
            ["All Events", "Only Attacks", "Only Normal"],
            horizontal=True
        )

        if view == "Only Attacks":
            df_v = df[df["Status"] == "ATTACK"]
        elif view == "Only Normal":
            df_v = df[df["Status"] == "NORMAL"]
        else:
            df_v = df

        st.dataframe(
            df_v.sort_values("Time").style.apply(highlight_attack_rows, axis=1),
            use_container_width=True,
            height=300
        )

        st.header("📊 Scenario Risk & Severity")

        for scenario in attack_scenarios:
            attack_count = len(
                df[(df["Scenario"] == scenario) & (df["Status"] == "ATTACK")]
            )
            risk = min(100, attack_count * 10)
            severity = risk_to_severity(risk)

            if severity == "CRITICAL":
                st.error(f"{scenario} | Risk {risk}/100 | CRITICAL")
            elif severity == "HIGH":
                st.warning(f"{scenario} | Risk {risk}/100 | HIGH")
            elif severity == "MEDIUM":
                st.info(f"{scenario} | Risk {risk}/100 | MEDIUM")
            else:
                st.success(f"{scenario} | Risk {risk}/100 | LOW")

# ======================================================
# MODE 2 — UPLOAD CSV (FEATURES UNCHANGED)
# ======================================================
if mode == "Upload CSV":

    st.header("📤 Uploaded Log Analysis")

    uploaded_file = st.file_uploader(
        "Upload Network Logs (CSV)",
        type=["csv"]
    )

    upload_view = st.radio(
        "View Mode",
        ["All Events", "Only Attacks", "Only Normal"]
    )

    if uploaded_file:
        uploaded_df = pd.read_csv(uploaded_file)
        uploaded_df["Time"] = pd.to_datetime(uploaded_df["Time"], errors="coerce")

        if upload_view == "Only Attacks":
            df_u = uploaded_df[uploaded_df["Status"] == "ATTACK"]
        elif upload_view == "Only Normal":
            df_u = uploaded_df[uploaded_df["Status"] == "NORMAL"]
        else:
            df_u = uploaded_df

        st.dataframe(
            df_u.sort_values("Time").style.apply(highlight_attack_rows, axis=1),
            use_container_width=True,
            height=300
        )

        st.header("📊 Uploaded Scenario Risk & Severity")

        for scenario in uploaded_df["Scenario"].unique():
            attack_count = len(
                uploaded_df[
                    (uploaded_df["Scenario"] == scenario) &
                    (uploaded_df["Status"] == "ATTACK")
                ]
            )
            risk = min(100, attack_count * 10)
            severity = risk_to_severity(risk)

            if severity == "CRITICAL":
                st.error(f"{scenario} | Risk {risk}/100 | CRITICAL")
            elif severity == "HIGH":
                st.warning(f"{scenario} | Risk {risk}/100 | HIGH")
            elif severity == "MEDIUM":
                st.info(f"{scenario} | Risk {risk}/100 | MEDIUM")
            else:
                st.success(f"{scenario} | Risk {risk}/100 | LOW")
