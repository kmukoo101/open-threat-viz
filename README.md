# Open Threat Viz

This is an app that helps analysts and security teams visualize and understand live open-source threat intelligence (OSINT). It aggregates, parses, and displays threat data from publicly available feeds, offering insights through interactive dashboards, graphs, and optional machine learning analysis.

## Features

- **Live Threat Feeds**: Pulls and parses real-time OSINT from trusted sources such as AbuseIPDB, URLHaus, and ThreatFox.
- **Threat Dashboard**: View and interact with threat indicators in a clean visual format.
- **Threat Graphs**: Explore relationships between indicators using graph visualizations.
- **Anomaly Detection (Optional)**: Identify unusual patterns using basic unsupervised learning.
- **GeoIP Lookup**: Maps IPs to countries using a free GeoIP database.

## OSINT Sources

- [AbuseIPDB](https://abuseipdb.com/)
- [URLHaus](https://urlhaus.abuse.ch/)
- [ThreatFox](https://threatfox.abuse.ch/)
- [Any.run Feeds](https://any.run/)
- [PhishTank](https://phishtank.org/)

## Getting Started

1. **Clone the repository**

   ```bash
   git clone https://github.com/yourusername/open-threat-viz.git
   cd open-threat-viz
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Run app**

   ```bash
   streamlit run app/main.py
   ```

