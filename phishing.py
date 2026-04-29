import streamlit as st
import re

# 1. Styling the Dashboard
st.set_page_config(page_title="PhishShield AI", page_icon="🛡️")

st.markdown("""
    <style>
    .stApp { background-color: #f0f2f6; }
    h1 { color: #1e3a8a; }
    .risk-high { color: #dc2626; font-weight: bold; font-size: 24px; }
    .risk-low { color: #16a34a; font-weight: bold; font-size: 24px; }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ PhishShield Identifier")
st.subheader("Heuristic Security Analysis")

# 2. Input Fields
with st.expander("📩 Enter Email Details", expanded=True):
    sender = st.text_input("Sender Email:", placeholder="e.g., security-alert@support-verify.net")
    subject = st.text_input("Subject Line:", placeholder="e.g., Your account will be suspended in 2 hours!")
    body = st.text_area("Email Body Content:", height=150)

# 3. The Detection Engine
if st.button("RUN SECURITY SCAN"):
    score = 0
    reasons = []

    # Check 1: Urgent Keywords (Heuristic Analysis)
    urgent_words = ['urgent', 'immediate', 'suspended', 'blocked', 'unauthorized', 'security alert', 'action required']
    found_urgency = [word for word in urgent_words if word in subject.lower() or word in body.lower()]
    if found_urgency:
        score += 25
        reasons.append(f"⚠️ High Urgency detected: {', '.join(found_urgency)}")

    # Check 2: Suspicious Sender Domain
    # Checking for common 'look-alike' domains
    if sender:
        if "@" in sender:
            domain = sender.split("@")[1]
            if any(x in domain for x in ['verify', 'secure', 'update', 'support-']):
                score += 30
                reasons.append("⚠️ Suspicious keywords found in sender domain.")
            if domain.endswith(('.xyz', '.info', '.top', '.click')):
                score += 15
                reasons.append("⚠️ Uses a high-risk Top-Level Domain (TLD).")

    # Check 3: Financial/Credential Requests
    data_requests = ['password', 'otp', 'credit card', 'bank detail', 'login', 'credentials', 'verify your identity']
    found_requests = [word for word in data_requests if word in body.lower()]
    if found_requests:
        score += 30
        reasons.append("🚨 Request for sensitive credentials/financial data found.")

    # 4. Display Results
    st.divider()
    risk_level = "HIGH" if score > 50 else "MEDIUM" if score > 20 else "LOW"
    
    col1, col2 = st.columns(2)
    with col1:
        st.write("### Risk Assessment:")
        if risk_level == "HIGH":
            st.markdown(f"<span class='risk-high'>🚨 {risk_level} RISK ({score}%)</span>", unsafe_allow_html=True)
        else:
            st.markdown(f"<span class='risk-low'>✅ {risk_level} RISK ({score}%)</span>", unsafe_allow_html=True)

    with col2:
        st.write("### Security Analysis:")
        if reasons:
            for r in reasons:
                st.write(r)
        else:
            st.write("No immediate red flags detected.")

st.markdown("---")
st.caption("Note: This is a heuristic tool for educational purposes. Always check the official source.")
