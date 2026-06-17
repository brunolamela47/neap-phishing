# backend/geoip.py

# ─────────────────────────────────────────
# NEAP — Network Email Anti-Phishing
# IP Geolocation via ip-api.com (free)
# ─────────────────────────────────────────

import requests
import re

def extract_sender_ip(msg) -> str:
    """Extract sender IP from email Received headers."""
    try:
        received_headers = msg.get_all("Received", [])
        if not received_headers:
            return None

        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

        for header in reversed(received_headers):
            ips = re.findall(ip_pattern, header)
            for ip in ips:
                # Skip private/local IPs
                if not ip.startswith(('10.', '192.168.', '127.', '172.', '0.')):
                    return ip
    except:
        pass
    return None


def geolocate_ip(ip: str) -> dict:
    """Get country, city and coordinates from IP using ip-api.com."""
    if not ip:
        return {}

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5,
            params={"fields": "status,country,countryCode,city,lat,lon,isp,org"}
        )
        data = response.json()

        if data.get("status") == "success":
            return {
                "ip":           ip,
                "country":      data.get("country"),
                "country_code": data.get("countryCode"),
                "city":         data.get("city"),
                "lat":          data.get("lat"),
                "lon":          data.get("lon"),
                "isp":          data.get("isp"),
                "org":          data.get("org")
            }
    except Exception as e:
        print(f"GeoIP error: {e}")

    return {"ip": ip}