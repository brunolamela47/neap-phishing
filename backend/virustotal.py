# backend/virustotal.py

# ─────────────────────────────────────────
# NEAP — Network Email Anti-Phishing
# VirusTotal URL & Hash Analysis
# ─────────────────────────────────────────

import re
import requests
import time

VT_API_KEY = "aef781d550698d38f00de6ce0ae34f01085d274d47bf6529c0c92a32be5744ab"
VT_BASE_URL = "https://www.virustotal.com/api/v3"

HEADERS = {
    "x-apikey": VT_API_KEY,
    "Content-Type": "application/x-www-form-urlencoded"
}


# ─── Extract URLs from email body ───
def extract_urls(text: str) -> list:
    """Extract all URLs from email body."""
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(pattern, text)
    # Remove duplicates
    return list(set(urls))


# ─── Scan URL ───
def scan_url(url: str) -> dict:
    """Submit URL to VirusTotal and get analysis."""
    try:
        # Submit URL
        response = requests.post(
            f"{VT_BASE_URL}/urls",
            headers=HEADERS,
            data={"url": url},
            timeout=15
        )

        if response.status_code != 200:
            return {"error": f"Submit failed: {response.status_code}", "url": url}

        analysis_id = response.json()["data"]["id"]

        # ─── Wait and retry until complete ───
        for attempt in range(10):
            time.sleep(5)

            analysis = requests.get(
                f"{VT_BASE_URL}/analyses/{analysis_id}",
                headers=HEADERS,
                timeout=15
            )

            if analysis.status_code != 200:
                continue

            data   = analysis.json()
            status = data["data"]["attributes"]["status"]
            stats  = data["data"]["attributes"]["stats"]

            if status == "completed":
                malicious  = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless   = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total      = malicious + suspicious + harmless + undetected

                return {
                    "url":        url,
                    "malicious":  malicious,
                    "suspicious": suspicious,
                    "harmless":   harmless,
                    "undetected": undetected,
                    "total":      total,
                    "safe":       malicious == 0 and suspicious == 0,
                    "verdict":    "MALICIOUS" if malicious > 0 else "SUSPICIOUS" if suspicious > 0 else "CLEAN"
                }

        return {"error": "Timeout — analysis not completed", "url": url}

    except requests.exceptions.Timeout:
        return {"error": "Timeout", "url": url}
    except Exception as e:
        return {"error": str(e), "url": url}

# ─── Scan multiple URLs ───
def scan_urls(urls: list) -> list:
    """Scan multiple URLs — respects rate limit (4/min)."""
    results = []
    for i, url in enumerate(urls[:5]):  # Max 5 URLs per email
        result = scan_url(url)
        results.append(result)
        if i < len(urls) - 1:
            time.sleep(15)  # 4 requests/min limit
    return results


if __name__ == "__main__":
    url = "https://www.eicar.org/download/eicar.com"
    
    # Step 1 - Submit
    response = requests.post(
        f"{VT_BASE_URL}/urls",
        headers=HEADERS,
        data={"url": url},
        timeout=15
    )
    print(f"Submit status: {response.status_code}")
    analysis_id = response.json()["data"]["id"]
    print(f"Analysis ID: {analysis_id}")
    
    # ─── Wait and retry until complete ───
    for attempt in range(10):
        time.sleep(5)
        print(f"Checking... attempt {attempt + 1}")
        
        analysis = requests.get(
            f"{VT_BASE_URL}/analyses/{analysis_id}",
            headers=HEADERS,
            timeout=15
        )
        
        data   = analysis.json()
        status = data["data"]["attributes"]["status"]
        stats  = data["data"]["attributes"]["stats"]
        
        print(f"Status: {status}")
        print(f"Stats: {stats}")
        
        # Stop when complete
        if status == "completed":
            print(f"\n✅ FINAL RESULT:")
            print(f"Malicious:  {stats['malicious']}")
            print(f"Suspicious: {stats['suspicious']}")
            print(f"Harmless:   {stats['harmless']}")
            print(f"Total:      {sum(stats.values())}")
            break