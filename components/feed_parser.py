import requests
from typing import List, Dict
import xml.etree.ElementTree as ET

OSINT_SOURCES = {
    "AlienVault OTX (Pulse RSS)": "https://otx.alienvault.com/feeds/full.xml",
    "Abuse.ch Feodo Tracker": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "URLhaus": "https://urlhaus.abuse.ch/downloads/json/",
    "EmergingThreats Rules": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
}

def fetch_feed(url: str) -> str:
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        return f"Error fetching {url}: {e}"

def parse_et_blocklist(raw_text: str) -> List[Dict[str, str]]:
    lines = raw_text.splitlines()
    iocs = []
    for line in lines:
        if line.strip() and not line.startswith("#"):
            iocs.append({"type": "IP", "value": line.strip()})
    return iocs

def parse_abusech_json(raw_json: str) -> List[Dict[str, str]]:
    try:
        data = requests.get(raw_json).json()
        iocs = []
        for entry in data.get("urls", []):
            iocs.append({
                "type": "URL",
                "value": entry.get("url"),
                "source": entry.get("threat", "unknown")
            })
        return iocs
    except Exception:
        return []

def parse_alienvault_rss(raw_xml: str) -> List[Dict[str, str]]:
    try:
        root = ET.fromstring(raw_xml)
        items = root.findall(".//item")
        iocs = []
        for item in items:
            title = item.findtext("title")
            link = item.findtext("link")
            if title:
                iocs.append({"type": "Pulse", "value": title, "link": link})
        return iocs
    except ET.ParseError:
        return []

def get_parsed_iocs() -> Dict[str, List[Dict[str, str]]]:
    """Fetch and parse all supported feeds, return dict of parsed IOCs"""
    results = {}

    for name, url in OSINT_SOURCES.items():
        raw = fetch_feed(url)
        if "AlienVault" in name:
            results[name] = parse_alienvault_rss(raw)
        elif "Feodo" in name:
            results[name] = parse_abusech_json(url)
        elif "URLhaus" in name:
            results[name] = parse_abusech_json(url)
        elif "EmergingThreats" in name:
            results[name] = parse_et_blocklist(raw)
        else:
            results[name] = [{"type": "raw", "value": raw[:300]}]  # Fallback raw preview

    return results
