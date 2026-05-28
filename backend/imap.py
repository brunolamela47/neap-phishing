# backend/imap.py

# ─────────────────────────────────────────
# NEAP — Network Email Anti-Phishing
# IMAP Email Fetcher
# ─────────────────────────────────────────

import imapclient
import email
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


def detect_server(email_address: str) -> str:
    """Detects IMAP server from email address."""
    domain = email_address.split("@")[-1].lower()

    if "gmail" in domain:    return IMAP_SERVERS["gmail"]
    if "outlook" in domain:  return IMAP_SERVERS["outlook"]
    if "hotmail" in domain:  return IMAP_SERVERS["hotmail"]
    if "yahoo" in domain:    return IMAP_SERVERS["yahoo"]

    return f"imap.{domain}"


def decode_str(value):
    """Decodes email header strings."""
    if not value:
        return ""
    decoded, encoding = decode_header(value)[0]
    if isinstance(decoded, bytes):
        return decoded.decode(encoding or "utf-8", errors="ignore")
    return decoded


def get_email_body(msg) -> str:
    """Extracts plain text body from email."""
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
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

    return body[:2000]  # limit to 2000 chars


def get_auth_results(msg) -> dict:
    """Extracts SPF/DKIM/DMARC from email headers."""
    spf   = "NONE"
    dkim  = "NONE"
    dmarc = "NONE"

    # Check all possible header variations
    headers_to_check = [
        "Authentication-Results",
        "ARC-Authentication-Results", 
        "Received-SPF",
        "X-Google-DKIM-Signature",
        "DKIM-Signature",
    ]

    auth = ""
    for header in headers_to_check:
        value = msg.get(header, "")
        if value:
            auth += value.lower() + " "

    # SPF
    if "spf=pass" in auth:      spf = "PASS"
    elif "spf=fail" in auth:    spf = "FAIL"
    elif "spf=softfail" in auth: spf = "FAIL"

    # DKIM
    if "dkim=pass" in auth:     dkim = "PASS"
    elif "dkim=fail" in auth:   dkim = "FAIL"

    # DMARC
    if "dmarc=pass" in auth:    dmarc = "PASS"
    elif "dmarc=fail" in auth:  dmarc = "FAIL"

    # Received-SPF specific
    received_spf = msg.get("Received-SPF", "").lower()
    if received_spf:
        if "pass" in received_spf:    spf = "PASS"
        elif "fail" in received_spf:  spf = "FAIL"

    return {"spf": spf, "dkim": dkim, "dmarc": dmarc}

def fetch_emails(email_address: str, password: str, limit: int = 20) -> dict:
    """
    Connects to IMAP server and fetches latest emails.
    Returns list of emails with sender, subject and body.
    """
    server_host = detect_server(email_address)

    try:
        # Connect
        client = imapclient.IMAPClient(server_host, ssl=True)
        client.login(email_address, password)

        # Select inbox
        client.select_folder("INBOX")

        # Fetch latest emails
        messages = client.search(["ALL"])
        messages = messages[-limit:]  # last N emails

        emails = []

        for uid in reversed(messages):
            try:
                raw = client.fetch([uid], ["RFC822"])
                msg = email.message_from_bytes(raw[uid][b"RFC822"])

                sender  = decode_str(msg.get("From", ""))
                subject = decode_str(msg.get("Subject", "No Subject"))
                body    = get_email_body(msg)
                auth = get_auth_results(msg)
                spf   = auth["spf"]
                dkim  = auth["dkim"]
                dmarc = auth["dmarc"]

                # Try to extract SPF/DKIM/DMARC from headers
                received_spf = msg.get("Received-SPF", "")
                if "pass" in received_spf.lower():    spf = "PASS"
                elif "fail" in received_spf.lower():  spf = "FAIL"

                auth_results = msg.get("Authentication-Results", "")
                if "dkim=pass" in auth_results.lower():   dkim = "PASS"
                elif "dkim=fail" in auth_results.lower(): dkim = "FAIL"
                if "dmarc=pass" in auth_results.lower():   dmarc = "PASS"
                elif "dmarc=fail" in auth_results.lower(): dmarc = "FAIL"

                emails.append({
                    "remetente": sender,
                    "assunto":   subject,
                    "corpo":     body,
                    "spf":       spf,
                    "dkim":      dkim,
                    "dmarc":     dmarc
                })

            except Exception as e:
                continue

        client.logout()

        return {"success": True, "emails": emails, "count": len(emails)}

    except imapclient.exceptions.LoginError:
        return {"success": False, "error": "Invalid email or password"}
    except Exception as e:
        return {"success": False, "error": str(e)}
