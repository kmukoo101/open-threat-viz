import streamlit as st
import os
import json
import pandas as pd
import matplotlib.pyplot as plt

DATA_DIR = "data/sample_feeds"
st.set_page_config(layout="wide")
st.title("Threat Intelligence Feeds")
st.caption("Live data synced from CIRCL, abuse.ch, and Malpedia")

# ---------- 1. CIRCL OSINT ----------
st.header("CIRCL OSINT Feed")

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
            "Link": f"https://www.circl.lu/doc/misp/feed-osint/current/{event.get('uuid')}.json"
        }
        rows.append(row)

    df_circl = pd.DataFrame(rows)

    search = st.text_input("🔍 Search CIRCL events", "")
    if search:
        df_circl = df_circl[df_circl["Info"].str.contains(search, case=False)]

    df_circl_display = df_circl[["Date", "Info", "Threat Level", "Link"]]
    st.dataframe(df_circl_display, use_container_width=True)
else:
    st.warning("CIRCL feed not found. Please run `update_feeds.py`.")

# ---------- 2. abuse.ch SSL Blacklist ----------
st.header("SSL Blacklist (abuse.ch)")

ssl_path = os.path.join(DATA_DIR, "sslblacklist.csv")
if os.path.exists(ssl_path):
    try:
        df_ssl = pd.read_csv(ssl_path, comment="#")
        col1, col2 = st.columns(2)
        with col1:
            st.text_input("🔍 Search by IP", key="ssl_ip", on_change=lambda: None)
        with col2:
            st.text_input("🔍 Search by SHA1", key="ssl_sha1", on_change=lambda: None)

        st.dataframe(df_ssl.head(100), use_container_width=True)

        # Chart: Most common issuers
        st.subheader("Common Issuers in SSL Blacklist")
        if "issuer_cn" in df_ssl.columns:
            top_issuers = df_ssl["issuer_cn"].value_counts().head(10)
            fig, ax = plt.subplots()
            top_issuers.plot(kind="bar", ax=ax)
            ax.set_ylabel("Count")
            ax.set_title("Top SSL Issuers")
            st.pyplot(fig)
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
                "Country": info.get("country", "Unknown"),
                "Motivation": info.get("motivations", [])[0] if info.get("motivations") else "Unknown",
                "Description": info.get("description", "")[:120] + "..."
            })

        df_malpedia = pd.DataFrame(rows)

        # Filter
        country_filter = st.selectbox("🌍 Filter by country", ["All"] + sorted(df_malpedia["Country"].unique().tolist()))
        if country_filter != "All":
            df_malpedia = df_malpedia[df_malpedia["Country"] == country_filter]

        st.dataframe(df_malpedia, use_container_width=True)

        # Chart: Threat Actors by Country
        st.subheader("Threat Actors by Country")
        country_counts = df_malpedia["Country"].value_counts().head(10)
        fig2, ax2 = plt.subplots()
        country_counts.plot(kind="bar", ax=ax2)
        ax2.set_ylabel("Number of Actors")
        ax2.set_title("Top Threat Actor Countries")
        st.pyplot(fig2)
    else:
        st.error("No actor data found in malpedia JSON.")
else:
    st.warning("Malpedia feed not found. Please run `update_feeds.py`.")
