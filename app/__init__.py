"""
This file sets up core configurations and shared state for the app.
"""

import os
import streamlit as st

# Global config that can be accessed across pages
st.set_page_config(
    page_title="OpenThreatViz",
    page_icon="🛡️",
    layout="wide"
)

# Cache shared data sources, like sample feeds
@st.cache_data(show_spinner=False)
def load_sample_data():
    import pandas as pd
    path = os.path.join("data", "sample_feeds", "threat_sample.csv")
    if os.path.exists(path):
        return pd.read_csv(path)
    return pd.DataFrame()

# Load and make available across the app
sample_data = load_sample_data()
