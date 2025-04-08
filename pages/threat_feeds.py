import streamlit as st
import os
import json
import pandas as pd

DATA_DIR = "data/sample_feeds"

st.title("🌐 Threat Intelligence Feeds")
st.caption("Live data synced from CIRCL, abuse.ch, and Malpedia")

# ---------- 1. CIRCL OSINT ----------
st.header("🧠 CIRCL OSINT Feed")

circl_path = os.path.join(DATA_DIR, "circl_events.json")
if os.path.exists(circl_path):
    with open(circl_path, "r") as f:
        event_list = json.load(f)

    rows = []
    for event in event_list:
        row = {
            "Info": event.get("info", ""),
            "Date": event.get("date", ""),
            "Threat Level": event.get("threat_level_id", ""),
            "UUID": event.get("uuid", ""),
        }
        rows.append(row)

    df_circl = pd.DataFrame(rows)
    st.dataframe(df_circl)
else:
    st.warning("CIRCL feed not found. Please run `update_feeds.py`.")

# ---------- 2. abuse.ch SSL Blacklist ----------
st.header("🔒 SSL Blacklist (abuse.ch)")

ssl_path = os.path.join(DATA_DIR, "sslblacklist.csv")
if os.path.exists(ssl_path):
    try:
        df_ssl = pd.read_csv(ssl_path, comment="#")
        st.dataframe(df_ssl.head(100))  # limit rows for speed
    except Exception as e:
        st.error(f"Error loading SSL blacklist: {e}")
else:
    st.warning("SSL blacklist feed not found. Please run `update_feeds.py`.")

# ---------- 3. Malpedia Threat Actors ----------
st.header("🎭 Malpedia Threat Actors")

malpedia_path = os.path.join(DATA_DIR, "malpedia_actors.json")
if os.path.exists(malpedia_path):
    with open(malpedia_path, "r") as f:
        data = json.load(f)

    if "data" in data:
        actors = data["data"]
        rows = []
        for name, info in actors.items():
            rows.append({
                "Actor": name,
                "Country": info.get("country", ""),
                "Motivation": info.get("motivations", [])[0] if info.get("motivations") else "",
                "Description": info.get("description", "")[:100] + "..."  # shortened
            })

        df_malpedia = pd.DataFrame(rows)
        st.dataframe(df_malpedia)
    else:
        st.error("No actor data found in malpedia JSON.")
else:
    st.warning("Malpedia feed not found. Please run `update_feeds.py`.")
