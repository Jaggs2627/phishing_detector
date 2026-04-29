import streamlit as st
import re

# 1. Dashboard Styling
st.set_page_config(page_title="PhishShield AI", page_icon="🛡️")

st.markdown("""
    <style>
    .stApp { background-color: #f8fafc; }
    .risk-high { color: #e11d48; font-size: 32px; font-weight: bold; text-shadow: 1px 1px 2px rgba(0,0,0,0.1); }
    .risk-med { color: #d97706; font-size: 32px; font-weight: bold; }
    .risk-low { color: #059669; font-size: 32px; font-weight: bold; }
    .reason-box { background-color: #ffffff; padding: 15px; border-radius: 10px; border-left: 5px solid #1e3a8a; margin-bottom: 10px; }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ PhishShield AI")
st.write("---")

# 2. Input Section
with st.container():
    col_a, col_b = st.columns([1, 1])
    with col_a:
        sender = st.text_input("👤 Sender Email:", placeholder="security@bank-verify.info")
    with col_b:
        subject = st.text_input("✉️ Subject Line:", placeholder="Action Required: Your account is suspended")
    
    body = st.text_area("📄 Email Body Content:", height=200, placeholder="Paste the full email text here...")

# 3. The Detection Engine
if st.button("🚀 EXECUTE SECURITY SCAN"):
    if not body and not subject:
        st.error("Please provide at least a subject or body to analyze.")
    else:
        score = 0
        reasons = []
        full_text = (subject + " " + body).lower()

        # --- HEURISTIC 1: URGENCY & THREATS ---
        # Using Regex to find word roots (e.g., 'suspend' catches 'suspended', 'suspending')
        if re.search(r"urgent|immediat|action required|suspended|blocked|unauthorized|restricted|security alert", full_text):
            score += 30
            reasons.append("⚠️ **Urgency/Threat detected:** Language designed to create panic.")

        # --- HEURISTIC 2: CREDENTIAL HARVESTING ---
        if re.search(r"password|login|credentials|verify|update account|bank|credit card|otp|ssn|identity", full_text):
            score += 35
            reasons.append("🚨 **Credential Harvesting:** Request for sensitive login or personal info.")

        # --- HEURISTIC 3: LINK & CALL TO ACTION ---
        links = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', full_text)
        if len(links) > 0:
            score += 15
            reasons.append(f"🔗 **Link Detection:** Contains {len(links)} external link(s).")
        
        if re.search(r"click here|link below|login here|follow this link", full_text):
            score += 10
            reasons.append("🖱️ **Call to Action:** Uses phrasing typical of phishing redirects.")

        # --- HEURISTIC 4: SENDER ANALYSIS ---
        if sender:
            domain = sender.lower().split("@")[-1]
            if any(x in domain for x in ['verify', 'secure', 'update', 'support-']):
                score += 25
                reasons.append("🌐 **Domain Spoofing:** Suspicious keywords found in the sender domain.")
            if domain.endswith(('.xyz', '.info', '.top', '.click', '.biz', '.online')):
                score += 15
                reasons.append(f"🚩 **High-Risk TLD:** The domain ends in .{domain.split('.')[-1]}, commonly used in phishing.")

        # Cap the score at 100%
        final_score = min(score, 100)

        # 4. Display Results
        st.write("---")
        res_col1, res_col2 = st.columns([1, 1])

        with res_col1:
            st.write("### 📊 Security Assessment")
            if final_score >= 70:
                st.markdown(f"<p class='risk-high'>HIGH RISK ({final_score}%)</p>", unsafe_allow_html=True)
                st.error("DANGER: This email matches multiple phishing patterns. Do not click any links.")
            elif final_score >= 30:
                st.markdown(f"<p class='risk-med'>MEDIUM RISK ({final_score}%)</p>", unsafe_allow_html=True)
                st.warning("CAUTION: Some suspicious elements were found. Verify the sender independently.")
            else:
                st.markdown(f"<p class='risk-low'>LOW RISK ({final_score}%)</p>", unsafe_allow_html=True)
                st.success("SAFE: No major phishing indicators found.")

        with res_col2:
            st.write("### 🔍 Technical Findings")
            if reasons:
                for r in reasons:
                    st.markdown(f"<div class='reason-box'>{r}</div>", unsafe_allow_html=True)
            else:
                st.write("No malicious heuristics triggered.")

st.markdown("---")
st.caption("🔒 Created for Nowrosjee Wadia College Cyber Security Project | Educational Tool")
