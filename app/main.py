import streamlit as st

# Page configuration
st.set_page_config(
    page_title="Open Threat Viz",
    page_icon="🛰️",
    layout="wide"
)

# Sidebar navigation
st.sidebar.title("📡 Open Threat Viz")
page = st.sidebar.radio("Go to", ["Dashboard", "Threat Feed", "Analytics"])

# Routing
if page == "Dashboard":
    dashboard.show()
elif page == "Threat Feed":
    threat_feed.show()
elif page == "Analytics":
    analytics.show()
