import streamlit as st
import pandas as pd

# ---------- PAGE CONFIG ----------
st.set_page_config(
    page_title="Cyber Threat Reasoning Engine (CTRE)",
    page_icon="🛡️",
    layout="wide"
)


# ---------- HEADER ----------
st.markdown("## 🛡️ Cyber Threat Reasoning Engine (CTRE)")
st.caption("Scenario-based synthetic cyber threat reasoning & response")


# ---------- SCENARIO SELECTION ----------
scenario = st.selectbox(
    "Select Threat Scenario",
    [
        "IoT Device Compromise (Office Network)",
        "Insider Threat (Abnormal Access)",
        "Malware / Lateral Movement"
    ]
)

st.divider()

# ---------- LOAD DATA ----------
df = pd.read_csv("network_logs.csv")

# ---------- METRICS ----------
total = len(df)
normal = len(df[df["Status"] == "NORMAL"])
attack = len(df[df["Status"] == "ATTACK"])

m1, m2, m3 = st.columns(3)
m1.metric("Total Events", total)
m2.metric("Normal Events", normal)
m3.metric("Attack Events", attack)

st.divider()

# ---------- TABS (PROFESSIONAL UI) ----------
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(
    ["📊 Overview", "📋 Logs", "🧠 Attack Narrative", "🔮 What-If Impact", "🧩 Threat Evolution", "🛠️ Mitigation"]
)


# ================= TAB 1: OVERVIEW =================
with tab1:
    st.subheader("Scenario Overview")
    st.info(
        f"""
        **Selected Scenario:** {scenario}

        This system demonstrates how a single threat reasoning engine
        adapts across different cyber attack scenarios using synthetic data.
        """
    )

# ================= TAB 2: LOGS =================
with tab2:
    st.subheader("Event Logs")

    filter_type = st.radio(
        "Filter events:",
        ["All", "Attack Only", "Normal Only"],
        horizontal=True
    )

    if filter_type == "Attack Only":
        view_df = df[df["Status"] == "ATTACK"]
    elif filter_type == "Normal Only":
        view_df = df[df["Status"] == "NORMAL"]
    else:
        view_df = df

    for _, row in view_df.iterrows():
        if row["Status"] == "ATTACK":
            st.error(f"⏰ {row['Time']} | 🚨 ATTACK | {row['Activity']}")
        else:
            st.success(f"⏰ {row['Time']} | NORMAL | {row['Activity']}")

# ================= TAB 3: ATTACK NARRATIVE =================
with tab3:
    st.subheader("Attack Narrative")

    if scenario.startswith("IoT"):
        st.warning(
            "An IoT device inside an office network shows abnormal behavior, "
            "followed by repeated access attempts and suspicious DNS activity, "
            "indicating a possible device compromise."
        )
    elif scenario.startswith("Insider"):
        st.warning(
            "An internal user exhibits abnormal access behavior over time, "
            "suggesting potential misuse of legitimate credentials."
        )
    else:
        st.warning(
            "Multiple systems demonstrate abnormal communication patterns, "
            "indicating possible malware propagation or lateral movement."
        )

# ================= TAB 4: WHAT-IF IMPACT =================
with tab4:
    st.subheader("What-If Impact Analysis")

    if scenario.startswith("IoT"):
        st.error(
            "⚠️ If the attack continues, the compromised IoT device may be used "
            "as an entry point into the internal network."
        )
    elif scenario.startswith("Insider"):
        st.error(
            "⚠️ Continued abnormal access could lead to sensitive data leakage "
            "or system misuse."
        )
    else:
        st.error(
            "⚠️ Malware spread may escalate, causing disruption across "
            "multiple systems."
        )
# ================= TAB 5: IMPROVED THREAT EVOLUTION =================
with tab5:
    st.subheader("Threat Evolution (State-Based Reasoning)")

    attack_logs = df[df["Status"] == "ATTACK"]

    # -------- Determine State & Evidence --------
    evidence = []
    current_state = "Normal"
    next_state = "Suspicious"

    if len(attack_logs) > 0:
        if any("SSH" in a for a in attack_logs["Activity"]):
            current_state = "Attack Execution"
            next_state = "Potential Impact"
            evidence.append("Multiple SSH authentication failures detected")
        if any("DNS" in a for a in attack_logs["Activity"]):
            evidence.append("Unusual DNS request patterns observed")
        if len(evidence) > 1:
            current_state = "Attack Execution"

    # -------- Visual Timeline --------
    states = ["Normal", "Suspicious", "Attack Execution", "Potential Impact"]
    cols = st.columns(len(states))

    for i, state in enumerate(states):
        if state == current_state:
            cols[i].error(f"🔴 {state}\n(Current)")
        elif state == next_state:
            cols[i].warning(f"🟡 {state}\n(Possible Next)")
        else:
            cols[i].info(f"⚪ {state}")

    st.divider()

    # -------- Evidence Explanation --------
    st.markdown("### 🔍 Evidence Behind Current State")

    if evidence:
        for e in evidence:
            st.write(f"- {e}")
    else:
        st.write("- No suspicious indicators detected")

    st.divider()

    # -------- Scenario-Aware Explanation --------
    st.markdown("### 🧠 Evolution Explanation")

    if scenario.startswith("IoT"):
        st.info(
            "The IoT device transitioned from normal behavior to attack execution "
            "due to repeated unauthorized access attempts and abnormal DNS activity."
        )
    elif scenario.startswith("Insider"):
        st.info(
            "The system detected privilege misuse indicators, suggesting an insider-driven escalation."
        )
    else:
        st.info(
            "Observed behavior suggests malware-driven lateral movement across systems."
        )

    # -------- Next State Projection --------
    st.markdown("### 🔮 Next Possible State")

    st.warning(
        f"If the observed behavior continues, the system may transition into "
        f"**{next_state}**, requiring immediate response actions."
    )

    # ================= TAB 6: MITIGATION & RESPONSE =================
with tab6:
    st.subheader("Response & Mitigation Guidance")

    if scenario.startswith("IoT"):
        st.success(
            """
            **Recommended Actions:**
            - Isolate the affected IoT device from the network
            - Reset device credentials and update firmware
            - Monitor outbound traffic for anomalies
            - Apply network segmentation to limit exposure
            """
        )

    elif scenario.startswith("Insider"):
        st.success(
            """
            **Recommended Actions:**
            - Review user access and activity logs
            - Temporarily restrict suspicious user privileges
            - Enforce multi-factor authentication
            - Notify security and compliance teams
            """
        )

    else:
        st.success(
            """
            **Recommended Actions:**
            - Quarantine infected systems immediately
            - Run endpoint malware scans
            - Segment the network to prevent lateral movement
            - Restore systems from secure backups
            """
        )

    st.info(
        "These recommendations are **preventive and defensive** in nature, "
        "designed to support SOC analysts during incident response."
    )


# ---------- FOOTER ----------
st.caption("Cyber Threat Reasoning Engine (CTRE) • Scenario-based Threat Modeling Prototype")

