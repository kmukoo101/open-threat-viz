import os
import requests
from datetime import datetime

# Save files
SAVE_DIR = "data/sample_feeds"
os.makedirs(SAVE_DIR, exist_ok=True)

def download_file(url, filename):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        filepath = os.path.join(SAVE_DIR, filename)
        with open(filepath, "wb") as f:
            f.write(response.content)
        print(f"[✓] Downloaded: {filename}")
    except Exception as e:
        print(f"[!] Failed to download {filename}: {e}")

# 1. CIRCL OSINT MISP Feed (event index JSON)
download_file(
    "https://www.circl.lu/doc/misp/feed-osint/current/events.json",
    "circl_events.json"
)

# 2. Abuse.ch SSL Blacklist (CSV format)
download_file(
    "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
    "sslblacklist.csv"
)

# 3. Malpedia Threat Actor Index (JSON format)
download_file(
    "https://malpedia.caad.fkie.fraunhofer.de/api/get/actors",
    "malpedia_actors.json"
)

# TODO: add token to use
# future add for families, URLs, or full MISP bundles etc.
# https://malpedia.caad.fkie.fraunhofer.de/api/
