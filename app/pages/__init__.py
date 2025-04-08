"""
Initialization Page: Core config setup, feed verification, and sample data preview.
"""

import os
import json
import pandas as pd
import streamlit as st
import subprocess

# --- Core App Config ---
st.set_page_config(
    page_title="OpenThreatViz",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("Initialization & Feed Tools")
st.caption("Verify environment setup, preview data, and access admin tools.")

DATA_DIR = os.path.join("data", "sample_feeds")
required_files = {
    "CIRCL OSINT": "circl_events.json",
    "Malpedia Actors": "malpedia_actors.json",
    "SSL Blacklist": "sslblacklist.csv"
}

# --- Feed Status Check ---
st.subheader("Feed File Check")

missing = [f for f in required_files.values() if not os.path.exists(os.path.join(DATA_DIR, f))]

if missing:
    st.warning("The following feed files are missing:")
    for f in missing:
        st.code(f)
    if st.button("🔄 Run update_feeds.py"):
        with st.spinner("Fetching feeds..."):
            subprocess.run(["python", "update_feeds.py"])
        st.success("Feeds updated. Reload the page.")
else:
    st.success("All feed files are present.")

# --- Sample Data Preview (Shared Global Example) ---
@st.cache_data(show_spinner=False)
def load_sample_data():
    path = os.path.join(DATA_DIR, "threat_sample.csv")
    if os.path.exists(path):
        return pd.read_csv(path)
    return pd.DataFrame()

st.subheader("🔍 Sample Feed Preview")

sample_df = load_sample_data()
if not sample_df.empty:
    st.dataframe(sample_df, use_container_width=True)
else:
    st.info("No sample data available to preview.")

# --- Optional File Viewer ---
st.subheader("Browse Feed Directory")

feed_files = os.listdir(DATA_DIR)
selected = st.selectbox("Preview any file in feed directory", feed_files)

file_path = os.path.join(DATA_DIR, selected)
if selected.endswith(".json"):
    with open(file_path, "r") as f:
        try:
            st.json(json.load(f))
        except json.JSONDecodeError:
            st.error("Invalid JSON format.")
elif selected.endswith(".csv"):
    st.dataframe(pd.read_csv(file_path), use_container_width=True)

