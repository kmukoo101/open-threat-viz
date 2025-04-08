import requests
from datetime import datetime
from typing import Optional
import pytz

def fetch_json_feed(url: str, headers: Optional[dict] = None) -> Optional[dict]:
    """
    Fetch and return JSON data from a given URL.
    Returns None if request fails.
    """
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"[!] Failed to fetch feed from {url}: {e}")
        return None

def utc_to_local(utc_str: str, tz: str = "UTC") -> str:
    """
    Converts UTC timestamp string (ISO format) to specified timezone.
    Returns formatted string: 'YYYY-MM-DD HH:MM:SS TZ'
    """
    try:
        utc_dt = datetime.fromisoformat(utc_str.replace("Z", "+00:00"))
        local_dt = utc_dt.astimezone(pytz.timezone(tz))
        return local_dt.strftime('%Y-%m-%d %H:%M:%S %Z')
    except Exception:
        return utc_str  # Fallback if format is invalid

def normalize_ioc(value: str) -> str:
    """
    Basic normalization of IOCs such as domains/IPs (lowercase, strip).
    """
    return value.strip().lower()

def truncate_text(text: str, max_length: int = 80) -> str:
    """
    Shorten text for display with ellipsis.
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."

# geoip_db.mmdb
