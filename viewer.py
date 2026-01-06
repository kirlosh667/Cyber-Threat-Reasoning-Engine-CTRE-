import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import uuid

# =============================
# PAGE CONFIG
# =============================
st.set_page_config(
    page_title="CTRE – Cyber Threat Reasoning Engine",
    layout="wide"
)

# =============================
# UI STYLING
# =============================
st.markdown("""
<style>
.block-container { padding-top: 0.8rem; padding-bottom: 0.8rem; }
h1 { margin-bottom: 0.3rem; }
h2, h3 { margin-top: 0.6rem; margin-bottom: 0.3rem; }
.stTabs [data-baseweb="tab-list"] { gap: 8px; }
</style>
""", unsafe_allow_html=True)

# =============================
# TITLE
# =============================
st.title("CTRE – Cyber Threat Reasoning Engine")
st.caption("SOC-style cyber attack simulation, log analysis, and recovery practice platform.")

# =============================
# SESSION STATE
# =============================
if "logs" not in st.session_state:
    st.session_state.logs = []
if "simulation_ran" not in st.session_state:
    st.session_state.simulation_ran = False
if "practice_state" not in st.session_state:
    st.session_state.practice_state = {}
if "stage_index" not in st.session_state:
    st.session_state.stage_index = {}
if "auto_select_scenario" not in st.session_state:
    st.session_state.auto_select_scenario = None

# =============================
# HELPERS
# =============================
def highlight_attack_rows(row):
    if row["Status"] == "ATTACK":
        return ["background-color:#b30000;color:white;font-weight:bold"] * len(row)
    return [""] * len(row)

def calculate_attack_level(scale):
    if scale >= 5:
        return "CRITICAL"
    elif scale == 4:
        return "HIGH"
    elif scale >= 2:
        return "MEDIUM"
    return "LOW"

# =============================
# BEGINNER LEARNING DATA
# =============================
common_software_attacks = {
    "SQL Injection": {"why": "Improper input validation.", "impact": "Database compromise", "for": "Beginners"},
    "Brute Force Attacks": {"why": "Weak passwords.", "impact": "Account takeover", "for": "SOC beginners"},
    "DDoS Attacks": {"why": "Botnet abuse.", "impact": "Service outage", "for": "Network teams"},
    "Credential Abuse": {"why": "Credential reuse.", "impact": "Unauthorized access", "for": "SOC analysts"},
    "Command & Control (C2)": {"why": "Remote attacker control.", "impact": "Persistent breach", "for": "Intermediate"}
}

learning_to_scenario_map = {
    "SQL Injection": "Web Application SQL Injection",
    "Brute Force Attacks": "IoT Brute Force",
    "DDoS Attacks": "DDoS Traffic Flood",
    "Credential Abuse": "Enterprise Breach (Multi-Vector Attack)",
    "Command & Control (C2)": "DNS Tunneling"
}

# =============================
# SCENARIOS
# =============================
scenario_info = {
    "IoT Brute Force": {
        "description": "Attackers exploit weak or default credentials on IoT devices.",
        "stages": ["IoT device discovered", "Repeated SSH login attempts", "Credential compromise", "Privilege escalation"],
        "correct": ["Isolate IoT device", "Change credentials", "Disable SSH access", "Update firmware"],
        "wrong": ["Restart device only", "Ignore alerts"],
        "continuation": ["Botnet enrollment", "Lateral movement", "Persistent compromise"]
    },
    "DNS Tunneling": {
        "description": "Attackers hide C2 traffic inside DNS queries.",
        "stages": ["Suspicious DNS queries", "Encoded payloads", "C2 communication"],
        "correct": ["Block malicious domains", "Inspect DNS traffic", "Quarantine endpoint"],
        "wrong": ["Flush DNS cache only", "Ignore DNS logs"],
        "continuation": ["Data exfiltration", "Stealth persistence"]
    },
    "Web Application SQL Injection": {
        "description": "Attackers exploit vulnerable web application inputs.",
        "stages": ["Injection probe", "SQL exploit", "Database access"],
        "correct": ["Take application offline", "Patch vulnerable code", "Rotate DB credentials"],
        "wrong": ["Restart web server", "Ignore SQL errors"],
        "continuation": ["Sensitive data leakage", "Database compromise"]
    },
    "DDoS Traffic Flood": {
        "description": "Attackers overwhelm services with massive traffic.",
        "stages": ["Traffic spike", "Service degradation", "Outage"],
        "correct": ["Enable rate limiting", "Block malicious IPs", "Engage DDoS protection"],
        "wrong": ["Restart server", "Increase timeouts"],
        "continuation": ["Extended downtime", "Revenue loss"]
    },
    "Enterprise Breach (Multi-Vector Attack)": {
        "description": "A coordinated enterprise-scale attack.",
        "stages": ["Reconnaissance", "Initial access", "Command & Control", "Impact"],
        "correct": ["Isolate compromised systems", "Reset credentials", "Investigate persistence"],
        "wrong": ["Notify users only", "Restart systems"],
        "continuation": ["Enterprise-wide compromise", "Severe reputational damage"]
    }
}

# =============================
# SIDEBAR
# =============================
with st.sidebar:
    st.header("🧭 CTRE Control Panel")
    mode = st.radio("Mode", ["Scenario Controller", "Upload CSV"])
    st.divider()
    show_learning = st.checkbox("Show Common Software Attacks")

# =============================
# BEGINNER LEARNING
# =============================
if show_learning:
    atk = st.selectbox("Select attack", list(common_software_attacks.keys()))
    info = common_software_attacks[atk]
    st.write(f"**Why:** {info['why']}")
    st.write(f"**Impact:** {info['impact']}")
    st.write(f"**Who:** {info['for']}")
    mapped = learning_to_scenario_map.get(atk)
    if mapped:
        st.info(f"Practice using **{mapped}**")
        if st.button("▶ Practice this scenario"):
            st.session_state.auto_select_scenario = mapped

# =============================
# SCENARIO CONTROLLER
# =============================
if mode == "Scenario Controller":

    default_sel = [st.session_state.auto_select_scenario] if st.session_state.auto_select_scenario else []

    attack_scenarios = st.multiselect(
        "Select Attack Scenarios",
        list(scenario_info.keys()),
        default=default_sel
    )

    scenario_scales = {s: st.slider(f"{s} – Attack Scale", 1, 5, 2) for s in attack_scenarios}

    if st.button("🚀 Simulate Attacks"):
        st.session_state.logs = []
        st.session_state.practice_state = {}
        st.session_state.stage_index = {s: 0 for s in attack_scenarios}

        base_time = datetime.now()

        # ✅ NORMAL BASELINE LOGS
        for i in range(4):
            st.session_state.logs.append({
                "Time": base_time + timedelta(seconds=i * 3),
                "Scenario": "Baseline",
                "Activity": "Normal network activity",
                "Status": "NORMAL"
            })

        # 🔴 ATTACK LOGS
        for s in attack_scenarios:
            for i, stage in enumerate(scenario_info[s]["stages"]):
                st.session_state.logs.append({
                    "Time": base_time + timedelta(seconds=20 + i * 5),
                    "Scenario": s,
                    "Activity": stage,
                    "Status": "ATTACK"
                })

        st.session_state.simulation_ran = True

    if st.session_state.simulation_ran:
        tab1, tab2, tab3 = st.tabs(["📘 Scenario Explanation", "📄 Network Logs", "🛠 Recovery Practice"])

        # TAB 1 – SCENARIO + STAGES
        with tab1:
            for s in attack_scenarios:
                idx = st.session_state.stage_index[s]
                stages = scenario_info[s]["stages"]

                st.markdown(f"### {s}")
                st.write(scenario_info[s]["description"])
                st.info(f"Current Stage: **{stages[idx]}**")
                st.progress(int(((idx + 1) / len(stages)) * 100))
                st.write(" ➜ ".join(stages[:idx + 1]))

                if idx < len(stages) - 1:
                    if st.button("▶ Next Stage", key=f"next_{s}_{idx}"):
                        st.session_state.stage_index[s] += 1

                st.divider()

        # TAB 2 – LOG FILTER
        with tab2:
            df = pd.DataFrame(st.session_state.logs)
            view = st.radio("View Logs", ["All Events", "Only Attacks", "Only Normal"], horizontal=True)

            if view == "Only Attacks":
                df = df[df["Status"] == "ATTACK"]
            elif view == "Only Normal":
                df = df[df["Status"] == "NORMAL"]

            st.dataframe(df.style.apply(highlight_attack_rows, axis=1), height=260)

        # TAB 3 – RECOVERY PRACTICE
        with tab3:
            for s in attack_scenarios:
                if s not in st.session_state.practice_state:
                    st.session_state.practice_state[s] = {
                        "run_id": uuid.uuid4().hex,
                        "selected": set(),
                        "evaluated": False
                    }

                state = st.session_state.practice_state[s]
                correct = set(scenario_info[s]["correct"])
                level = calculate_attack_level(scenario_scales[s])

                st.markdown(f"#### 🔧 {s} | Level: {level}")

                actions = scenario_info[s]["correct"] + scenario_info[s]["wrong"]
                cols = st.columns(2)

                for i, a in enumerate(actions):
                    with cols[i % 2]:
                        if st.checkbox(a, key=f"{s}_{a}_{state['run_id']}"):
                            state["selected"].add(a)

                if st.button("Evaluate Recovery", key=f"eval_{s}_{state['run_id']}"):
                    state["evaluated"] = True

                if state["evaluated"]:
                    score = int(len(state["selected"] & correct) / len(correct) * 100)
                    st.progress(score)

                    for a in state["selected"]:
                         if a in correct:
                            st.success(f"✅ Correct: {a}")
                         else:
                            st.error(f"❌ Wrong: {a}")

                    st.markdown(f"### 📊 Score: **{len(state['selected'] & correct)} / {len(correct)}** ({score}%)")

                    with st.expander("⚠️ What happens if attack continues"):
                        for c in scenario_info[s]["continuation"]:
                            st.write("• " + c)

                if st.button("🔁 Re-Practice Scenario", key=f"reset_{s}_{state['run_id']}"):
                    st.session_state.practice_state[s] = {
                        "run_id": uuid.uuid4().hex,
                        "selected": set(),
                        "evaluated": False
                    }




# =============================
# CSV UPLOAD (ENHANCED – SAME AS SCENARIO CONTROLLER)
# =============================
if mode == "Upload CSV":
    file = st.file_uploader("Upload CSV", type=["csv"])

    if file:
        df = pd.read_csv(file)

        # 🔧 FIX STATUS COLUMN (CRITICAL)
        if "Status" in df.columns:
            df["Status"] = df["Status"].astype(str).str.strip().str.upper()

        st.subheader("📄 Uploaded Network Logs")

        # 🔍 LOG FILTER
        view = st.radio(
            "View Logs",
            ["All Events", "Only Attacks", "Only Normal"],
            horizontal=True
        )

        if view == "Only Attacks":
            df_view = df[df["Status"] == "ATTACK"]
        elif view == "Only Normal":
            df_view = df[df["Status"] == "NORMAL"]
        else:
            df_view = df

        st.dataframe(
            df_view.style.apply(highlight_attack_rows, axis=1),
            height=300
        )

        # 📊 SUMMARY
        if "Status" in df.columns:
            attack_count = (df["Status"] == "ATTACK").sum()
            normal_count = (df["Status"] == "NORMAL").sum()

            col1, col2 = st.columns(2)
            col1.metric("🚨 Attack Events", attack_count)
            col2.metric("✅ Normal Events", normal_count)

        # 🧠 REASONING (LIKE SCENARIO CONTROLLER)
        if attack_count > 0:
            st.subheader("🧠 Threat Reasoning")
            st.warning(
                "Attack patterns were detected in uploaded logs. "
                "CTRE correlates these events with known attack behaviors "
                "to support SOC-level investigation and response."
            )

            if "Attack_Category" in df.columns:
                with st.expander("🔍 Detected Attack Categories"):
                    for a in df[df["Status"] == "ATTACK"]["Attack_Category"].dropna().unique():
                        st.write(f"• {a}")
        else:
            st.success(
                "No attack activity detected. Logs represent normal system behavior."
            )
