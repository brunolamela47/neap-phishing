# backend/imap.py

# ─────────────────────────────────────────
# NEAP — Network Email Anti-Phishing
# IMAP Email Fetcher
# ─────────────────────────────────────────

import imapclient
import email
import re
from email.header import decode_header
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ─── IMAP Servers ───
IMAP_SERVERS = {
    "gmail":   "imap.gmail.com",
    "outlook": "imap-mail.outlook.com",
    "yahoo":   "imap.mail.yahoo.com",
    "hotmail": "imap-mail.outlook.com",
}

# ─── Private IP ranges to skip ───
PRIVATE_PREFIXES = ('10.', '192.168.', '127.', '172.', '0.', '::1', 'fe80')


def detect_server(email_address: str) -> str:
    domain = email_address.split("@")[-1].lower()
    if "gmail" in domain:   return IMAP_SERVERS["gmail"]
    if "outlook" in domain: return IMAP_SERVERS["outlook"]
    if "hotmail" in domain: return IMAP_SERVERS["hotmail"]
    if "yahoo" in domain:   return IMAP_SERVERS["yahoo"]
    return f"imap.{domain}"


def decode_str(value):
    if not value:
        return ""
    decoded, encoding = decode_header(value)[0]
    if isinstance(decoded, bytes):
        return decoded.decode(encoding or "utf-8", errors="ignore")
    return decoded


def get_email_body(msg) -> str:
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                    break
                except:
                    continue
    else:
        try:
            body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
        except:
            body = ""
    return body[:2000]


def get_auth_results(msg) -> dict:
    spf = dkim = dmarc = "NONE"

    auth = ""
    for header in ["Authentication-Results", "ARC-Authentication-Results", "Received-SPF", "DKIM-Signature"]:
        value = msg.get(header, "")
        if value:
            auth += value.lower() + " "

    if "spf=pass" in auth:       spf = "PASS"
    elif "spf=fail" in auth:     spf = "FAIL"
    elif "spf=softfail" in auth: spf = "FAIL"

    if "dkim=pass" in auth:  dkim = "PASS"
    elif "dkim=fail" in auth: dkim = "FAIL"

    if "dmarc=pass" in auth:  dmarc = "PASS"
    elif "dmarc=fail" in auth: dmarc = "FAIL"

    received_spf = msg.get("Received-SPF", "").lower()
    if received_spf:
        if "pass" in received_spf:  spf = "PASS"
        elif "fail" in received_spf: spf = "FAIL"

    return {"spf": spf, "dkim": dkim, "dmarc": dmarc}


def extract_sender_ip(msg) -> str:
    """
    Extract the real sender IP from Received headers.
    Skips private/local IPs and known Google/Microsoft mail servers.
    """
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    # Skip these known mail relay IPs
    skip_orgs = ['google', 'gmail', 'microsoft', 'outlook', 'yahoo', 'amazon', 'mx.']

    received_headers = msg.get_all("Received", [])
    if not received_headers:
        return None

    # Go through headers oldest first (most external = most interesting)
    for header in reversed(received_headers):
        header_lower = header.lower()

        # Skip if this is an internal Google/Microsoft hop
        if any(org in header_lower for org in skip_orgs):
            continue

        ips = re.findall(ip_pattern, header)
        for ip in ips:
            # Skip private ranges
            if any(ip.startswith(p) for p in PRIVATE_PREFIXES):
                continue
            # Skip invalid IPs
            parts = ip.split('.')
            if not all(0 <= int(p) <= 255 for p in parts):
                continue
            return ip

    # Fallback: any external IP from any header
    for header in reversed(received_headers):
        ips = re.findall(ip_pattern, header)
        for ip in ips:
            if not any(ip.startswith(p) for p in PRIVATE_PREFIXES):
                parts = ip.split('.')
                if all(0 <= int(p) <= 255 for p in parts):
                    return ip

    return None


def fetch_emails(email_address: str, password: str, limit: int = 20) -> dict:
    """Connects to IMAP and fetches latest emails with IP extraction."""
    server_host = detect_server(email_address)

    try:
        client = imapclient.IMAPClient(server_host, ssl=True)
        client.login(email_address, password)
        client.select_folder("INBOX")

        messages = client.search(["ALL"])
        messages = messages[-limit:]

        emails = []

        for uid in reversed(messages):
            try:
                raw = client.fetch([uid], ["RFC822"])
                msg = email.message_from_bytes(raw[uid][b"RFC822"])

                sender  = decode_str(msg.get("From", ""))
                subject = decode_str(msg.get("Subject", "No Subject"))
                body    = get_email_body(msg)
                auth    = get_auth_results(msg)
                ip      = extract_sender_ip(msg)

                print(f"Email: {subject[:30]} | IP: {ip}")

                emails.append({
                    "remetente": sender,
                    "assunto":   subject,
                    "corpo":     body,
                    "spf":       auth["spf"],
                    "dkim":      auth["dkim"],
                    "dmarc":     auth["dmarc"],
                    "ip_origem": ip
                })

            except Exception as e:
                print(f"Email parse error: {e}")
                continue

        client.logout()
        return {"success": True, "emails": emails, "count": len(emails)}

    except imapclient.exceptions.LoginError:
        return {"success": False, "error": "Invalid email or password"}
    except Exception as e:
        return {"success": False, "error": str(e)}