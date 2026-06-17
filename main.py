import os
import sys
import threading
import time
import uvicorn
import webview

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.main import app


def auto_imap_check():
    """Background thread that checks IMAP automatically."""
    import sys

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    from backend.imap import fetch_emails
    from database.database import get_connection
    from datetime import datetime
    from utils.crypto import decrypt
    from utils.score import calculate_score

    print("Auto IMAP check thread started!")

    while True:
        try:
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT IMAP_CREDENTIALS.email, IMAP_CREDENTIALS.password,
                       IMAP_CREDENTIALS.interval, IMAP_CREDENTIALS.last_check,
                       IMAP_CREDENTIALS.auto_check, USERS.username
                FROM IMAP_CREDENTIALS
                JOIN USERS ON IMAP_CREDENTIALS.id_user = USERS.id_user
            """)

            credentials = cursor.fetchall()
            conn.close()

            for cred in credentials:
                email = cred[0]
                password = decrypt(cred[1])
                interval = cred[2] or 30
                last_check = cred[3]
                auto_check = cred[4]
                username = cred[5]  # Recuperado da query SQL

                # ─── Skip if auto_check disabled ───
                if not auto_check:
                    print(f"Auto check disabled for {email} — skipping")
                    continue

                # ─── Check if enough time has passed ───
                if last_check:
                    last = datetime.fromisoformat(last_check)
                    diff = (datetime.now() - last).total_seconds() / 60
                    if diff < interval:
                        print(
                            f"Next check for {email} in {round(interval - diff)} minutes"
                        )
                        continue

                print(f"Auto IMAP check for {email}...")

                result = fetch_emails(email, password, limit=10)

                if result["success"]:
                    conn = get_connection()
                    cursor = conn.cursor()
                    phishing_count = 0
                    skipped = 0

                    for email_data in result["emails"]:
                        # ─── Skip duplicates ───
                        cursor.execute(
                            """
                            SELECT id_email FROM EMAILS
                            WHERE remetente = ? AND assunto = ?
                            LIMIT 1
                        """,
                            (email_data["remetente"], email_data["assunto"]),
                        )
                        if cursor.fetchone():
                            skipped += 1
                            continue

                        try:
                            score_result = calculate_score(
                                sender=email_data["remetente"],
                                subject=email_data["assunto"],
                                body=email_data["corpo"],
                                spf=email_data["spf"],
                                dkim=email_data["dkim"],
                                dmarc=email_data["dmarc"],
                            )
                            if not score_result:
                                continue
                        except Exception as e:
                            print(f"Score error: {e}")
                            continue

                        cursor.execute(
                            """
                            INSERT INTO EMAILS (remetente, assunto, corpo)
                            VALUES (?, ?, ?)
                        """,
                            (
                                email_data["remetente"],
                                email_data["assunto"],
                                email_data["corpo"],
                            ),
                        )
                        id_email = cursor.lastrowid

                        ai_details = score_result.get("ai_details", {})
                        cursor.execute(
                            """
                            INSERT INTO ANALISES (id_email, score, resultado, nivel_risco,
                                                 ai_verdict, ai_confidence, ai_reasons)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                            (
                                id_email,
                                score_result["final_score"],
                                score_result["result"],
                                score_result["risk_level"],
                                ai_details.get("verdict"),
                                ai_details.get("confidence"),
                                str(ai_details.get("reasons", [])),
                            ),
                        )
                        id_analise = cursor.lastrowid

                        cursor.execute(
                            """
                            INSERT INTO LOGS (id_analise, evento, spf, dkim, dmarc, ip_origem)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """,
                            (
                                id_analise,
                                "Auto IMAP check",
                                email_data["spf"],
                                email_data["dkim"],
                                email_data["dmarc"],
                                email_data.get("ip_origem"),
                            ),
                        )
                        id_log = cursor.lastrowid

                        if score_result["risk_level"] in ["HIGH", "CRITICAL"]:
                            cursor.execute(
                                """
                                INSERT INTO ALERTAS (id_log, tipo_alerta, estado_alerta)
                                VALUES (?, ?, ?)
                            """,
                                (id_log, score_result["risk_level"], "ACTIVE"),
                            )
                            phishing_count += 1

                    # ─── Update last_check ───
                    cursor.execute(
                        """
                        UPDATE IMAP_CREDENTIALS SET last_check = datetime('now')
                        WHERE email = ?
                    """,
                        (email,),
                    )

                    conn.commit()
                    conn.close()

                    print(
                        f"Auto check: {len(result['emails'])} fetched, {phishing_count} phishing, {skipped} duplicates skipped"
                    )

                    # ─── Notifications + Webhooks ───
                    if phishing_count > 0:
                        # Desktop notification
                        try:
                            from backend.notifications import notify_imap_check

                            notify_imap_check(
                                len(result["emails"]), phishing_count
                            )
                        except Exception as e:
                            print(f"Notification error: {e}")

                        # Webhook
                        try:
                            import asyncio
                            from database.database import (
                                get_connection as gc,
                            )
                            from backend.webhooks import send_webhooks

                            conn2 = gc()
                            cur2 = conn2.cursor()
                            cur2.execute(
                                """
                                SELECT discord_url, slack_url, telegram_token, telegram_chat_id
                                FROM WEBHOOK_SETTINGS
                                JOIN USERS ON WEBHOOK_SETTINGS.id_user = USERS.id_user
                                WHERE USERS.username = ? AND WEBHOOK_SETTINGS.active = 1
                            """,
                                (username,),
                            )
                            wh = cur2.fetchone()
                            conn2.close()

                            if wh and any(wh):
                                webhook_config = {
                                    "discord_url": wh[0],
                                    "slack_url": wh[1],
                                    "telegram_token": wh[2],
                                    "telegram_chat_id": wh[3],
                                }
                                email_alert = {
                                    "remetente": email,
                                    "assunto": f"{phishing_count} emails de phishing detetados",
                                    "score": 100,
                                    "nivel_risco": "CRITICAL",
                                    "resultado": "PHISHING",
                                    "data_hora": "",
                                }
                                asyncio.run(
                                    send_webhooks(email_alert, webhook_config)
                                )
                        except Exception as e:
                            print(f"Webhook error: {e}")

        except Exception as global_err:
            print(f"Global loop error: global_err")

        time.sleep(30)


# ─── Start FastAPI ───
def start_api():
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")


# ─── Wait for API ───
def wait_for_api():
    import urllib.request

    for _ in range(20):
        try:
            urllib.request.urlopen("http://127.0.0.1:8000")
            return True
        except:
            time.sleep(0.5)
    return False


# ─── Main ───
if __name__ == "__main__":
    # Start FastAPI in background thread
    thread = threading.Thread(target=start_api, daemon=True)
    thread.start()

    # Start auto IMAP check
    imap_thread = threading.Thread(target=auto_imap_check, daemon=True)
    imap_thread.start()

    print("Starting NEAP API...")
    wait_for_api()
    print("API ready!")

    # Get index.html path
    index = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "web", "index.html"
    )

    # Open PyWebView window
    window = webview.create_window(
        title="NEAP — Network Email Anti-Phishing",
        url=f"file:///{index}",
        width=1280,
        height=800,
        min_size=(1024, 600),
        resizable=True,
    )

    webview.start(debug=False)