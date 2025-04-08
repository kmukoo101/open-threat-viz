import streamlit as st
import os
import json
import pandas as pd
import matplotlib.pyplot as plt
import subprocess

DATA_DIR = "data/sample_feeds"
st.set_page_config(layout="wide")

# Sidebar controls
with st.sidebar:
    st.header("Controls")
    if st.button("Refresh CIRCL Feed"):
        subprocess.run(["python", "update_feeds.py"])
    if st.button("Refresh SSL Blacklist"):
        subprocess.run(["python", "update_feeds.py"])
    if st.button("Refresh Malpedia"):
        subprocess.run(["python", "update_feeds.py"])
    st.caption("Use these buttons to trigger updates in future versions.")

    malpedia_country_filter = None
    malpedia_path = os.path.join(DATA_DIR, "malpedia_actors.json")
    if os.path.exists(malpedia_path):
        with open(malpedia_path, "r") as f:
            data = json.load(f)
        if "data" in data:
            actors = data["data"]
            country_list = sorted(list({info.get("country", "Unknown") for info in actors.values()}))
            malpedia_country_filter = st.selectbox("Sidebar Filter: Malpedia Country", ["All"] + country_list)

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

    search = st.text_input("Search CIRCL events", "")
    threat_levels = sorted(df_circl["Threat Level"].unique().tolist())
    threat_filter = st.multiselect("Filter by Threat Level", threat_levels)
    date_range = st.date_input("Filter by Date Range", [])

    if search:
        df_circl = df_circl[df_circl["Info"].str.contains(search, case=False)]

    if threat_filter:
        df_circl = df_circl[df_circl["Threat Level"].isin(threat_filter)]

    if len(date_range) == 2:
        # If both start and end dates are selected, filter the CIRCL data by this date range
        df_circl["Date"] = pd.to_datetime(df_circl["Date"], errors='coerce')
        df_circl = df_circl[(df_circl["Date"] >= pd.to_datetime(date_range[0])) & (df_circl["Date"] <= pd.to_datetime(date_range[1]))]
        df_circl["Date"] = df_circl["Date"].dt.strftime('%Y-%m-%d')

    df_circl_display = df_circl[["Date", "Info", "Threat Level", "Link"]].copy()
    df_circl_display["Link"] = df_circl_display["Link"].apply(lambda x: f"[View JSON]({x})")

    st.markdown("**Event Table:** Click a link to open the MISP event JSON.")
    st.write(df_circl_display.to_markdown(index=False), unsafe_allow_html=True)

    csv = df_circl_display.to_csv(index=False).encode("utf-8")
    st.download_button("Download CIRCL Feed CSV", csv, "circl_events.csv", "text/csv")

    # Export full raw JSON for analysis
    raw_json = json.dumps(event_list, indent=2).encode("utf-8")
    st.download_button("Download Full CIRCL Feed JSON", raw_json, "circl_events.json", "application/json")

else:
    st.warning("CIRCL feed not found. Please run update_feeds.py.")

# ---------- 2. abuse.ch SSL Blacklist ----------
st.header("SSL Blacklist (abuse.ch)")

@st.cache_data

def load_ssl_blacklist(path):
    """Load the abuse.ch SSL blacklist CSV file.

    Uses Streamlit's cache to improve performance when reloading the same file.

    Args:
        path (str): Path to the CSV file.

    Returns:
        pd.DataFrame: Parsed DataFrame of SSL blacklist.
    """
    return pd.read_csv(path, comment="#")

ssl_path = os.path.join(DATA_DIR, "sslblacklist.csv")
if os.path.exists(ssl_path):
    try:
        df_ssl = load_ssl_blacklist(ssl_path)

        ip_filter = st.text_input("Search by IP")
        sha1_filter = st.text_input("Search by SHA1")

        df_filtered = df_ssl.copy()
        if ip_filter:
            df_filtered = df_filtered[df_filtered["ip"].astype(str).str.contains(ip_filter, case=False)]
        if sha1_filter:
            df_filtered = df_filtered[df_filtered["sha1_fingerprint"].astype(str).str.contains(sha1_filter, case=False)]

        show_all = st.checkbox("Show all results")
        if show_all:
            st.dataframe(df_filtered, use_container_width=True)
        else:
            st.dataframe(df_filtered.head(100), use_container_width=True)

        st.subheader("Common Issuers in SSL Blacklist")
        if "issuer_cn" in df_ssl.columns:
            top_issuers = df_ssl["issuer_cn"].value_counts().head(10)
            fig, ax = plt.subplots()
            top_issuers.plot(kind="bar", ax=ax)
            ax.set_ylabel("Count")
            ax.set_title("Top SSL Issuers")
            st.pyplot(fig)

        csv = df_filtered.to_csv(index=False).encode("utf-8")
        st.download_button("Download SSL Blacklist CSV", csv, "sslblacklist.csv", "text/csv")

    except Exception as e:
        st.error(f"Error loading SSL blacklist: {e}")
else:
    st.warning("SSL blacklist feed not found. Please run update_feeds.py.")

# ---------- 3. Malpedia Threat Actors ----------
st.header("Malpedia Threat Actors")

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
                "Full Description": info.get("description", "")
            })

        df_malpedia = pd.DataFrame(rows)

        # Filter the Malpedia dataframe by selected country from the sidebar dropdown
        if malpedia_country_filter and malpedia_country_filter != "All":
            df_malpedia = df_malpedia[df_malpedia["Country"] == malpedia_country_filter]

        st.dataframe(df_malpedia[["Actor", "Country", "Motivation"]], use_container_width=True)

        # Display full descriptions and filter them using keywords
        with st.expander("View Full Descriptions"):
            keyword_filter = st.text_input("Filter descriptions by actor or keyword")
            for _, row in df_malpedia.iterrows():
                if keyword_filter.lower() in row["Full Description"].lower() or keyword_filter.lower() in row["Actor"].lower():
                    st.markdown(f"**{row['Actor']}** - {row['Country']} ({row['Motivation']})")
                    st.markdown(row["Full Description"])
                    st.markdown("---")

        # This visualization shows the number of threat actors attributed to each country.
        # Toggle lets users switch between top 10 and full list for global or focused views.
        st.subheader("Threat Actors by Country")
        view_all_counts = st.checkbox("Show all countries")
        country_counts = df_malpedia["Country"].value_counts()
        if not view_all_counts:
            country_counts = country_counts.head(10)
        fig2, ax2 = plt.subplots()
        country_counts.plot(kind="bar", ax=ax2)
        ax2.set_ylabel("Number of Actors")
        ax2.set_title("Top Threat Actor Countries")
        st.pyplot(fig2)

        csv = df_malpedia.to_csv(index=False).encode("utf-8")
        st.download_button("Download Malpedia CSV", csv, "malpedia_actors.csv", "text/csv")

    else:
        st.error("No actor data found in Malpedia JSON.")
else:
    st.warning("Malpedia feed not found. Please run update_feeds.py.")
