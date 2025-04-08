import streamlit as st
from datetime import datetime

# Page configuration
st.set_page_config(
    page_title="Open Threat Viz",
    page_icon="🛰️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Stylized welcome screen
st.markdown("""
    <style>
    .big-title {
        font-size: 3em;
        font-weight: 700;
        padding-top: 1rem;
    }
    .subtle-text {
        font-size: 1.25em;
        color: #aaa;
    }
    .highlight-box {
        background-color: #111;
        padding: 1.5rem;
        border-radius: 10px;
        margin-top: 1rem;
        border-left: 4px solid #4CAF50;
    }
    </style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="big-title">Open Threat Viz</div>
<div class="subtle-text">Empowering defenders with real-time intelligence and elegant visual insights.</div>
""", unsafe_allow_html=True)

# Mission
st.markdown("""
<div class="highlight-box">
    <strong>Welcome to Open Threat Viz</strong><br>
    This platform is your open-source launchpad for:
    <ul>
        <li>Real-time threat feeds from CIRCL, abuse.ch, and Malpedia</li>
        <li>Visual intelligence for quick threat actor profiling</li>
        <li>Analyst-first interface for filtering, searching, and exporting data</li>
        <li>Designed for use in SOCs, research, education, and incident response</li>
    </ul>
    <br>
    <i>Start exploring with the sidebar on the left. New features are in active development.</i>
</div>
""", unsafe_allow_html=True)

# Footer
st.caption(f"App version 0.2.0 • Loaded on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
