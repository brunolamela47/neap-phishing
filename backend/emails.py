# backend/emails.py

# ─────────────────────────────────────────
# NEAP — Network Email Anti-Phishing
# Email Analysis Endpoints
# ─────────────────────────────────────────

from fastapi import APIRouter, HTTPException, Header
from typing import Optional
import asyncio
import sys
import os
from backend.ws_manager import manager

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.models import EmailAnalyzeModel, ResponseModel, IMAPModel
from database.database import get_connection
from utils.score import calculate_score
from backend.imap import fetch_emails

router = APIRouter()


# ─── Verify Token ───
def verify_token(authorization: str):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token")

    token = authorization.split(" ")[1]
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT SESSIONS.token, USERS.username, SESSIONS.expires_at
        FROM SESSIONS
        JOIN USERS ON SESSIONS.id_user = USERS.id_user
        WHERE SESSIONS.token = ?
    """, (token,))

    session = cursor.fetchone()
    conn.close()

    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")

    return session[1]


# ─── Get Webhook Config ───
def get_webhook_config(username: str) -> dict:
    """Get webhook config for user."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT discord_url, slack_url, telegram_token, telegram_chat_id
            FROM WEBHOOK_SETTINGS
            JOIN USERS ON WEBHOOK_SETTINGS.id_user = USERS.id_user
            WHERE USERS.username = ? AND WEBHOOK_SETTINGS.active = 1
        """, (username,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return {
                "discord_url":      row[0],
                "slack_url":        row[1],
                "telegram_token":   row[2],
                "telegram_chat_id": row[3]
            }
    except Exception as e:
        print(f"Webhook config error: {e}")
    return {}


# ─────────────────────────────────────────
# ANALYZE EMAIL
# ─────────────────────────────────────────
@router.post("/analyze", response_model=ResponseModel)
async def analyze_email(data: EmailAnalyzeModel, authorization: Optional[str] = Header(None)):
    username = verify_token(authorization)

    result = calculate_score(
        sender=data.remetente,
        subject=data.assunto,
        body=data.corpo,
        spf=data.spf,
        dkim=data.dkim,
        dmarc=data.dmarc
    )

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO EMAILS (remetente, assunto, corpo)
        VALUES (?, ?, ?)
    """, (data.remetente, data.assunto, data.corpo))
    id_email = cursor.lastrowid

    ai_details           = result.get("ai_details", {})
    ai_verdict           = ai_details.get("verdict", None)
    ai_conf              = ai_details.get("confidence", None)
    ai_reasons           = str(ai_details.get("reasons", []))
    impersonated_company = ai_details.get("impersonated_company", None)
    official_domain      = ai_details.get("official_domain", None)
    sender_domain        = ai_details.get("sender_domain", None)
    domain_match         = ai_details.get("domain_match", None)

    cursor.execute("""
        INSERT INTO ANALISES (id_email, score, resultado, nivel_risco,
                              ai_verdict, ai_confidence, ai_reasons,
                              impersonated_company, official_domain,
                              sender_domain, domain_match)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (id_email, result["final_score"], result["result"], result["risk_level"],
          ai_verdict, ai_conf, ai_reasons,
          impersonated_company, official_domain, sender_domain,
          1 if domain_match else 0 if domain_match is not None else None))
    id_analise = cursor.lastrowid

    cursor.execute("""
    INSERT INTO LOGS (id_analise, evento, spf, dkim, dmarc, ip_origem)
    VALUES (?, ?, ?, ?, ?, ?)
""", (id_analise, "IMAP auto-analysis", email_data["spf"], email_data["dkim"], email_data["dmarc"], email_data.get("ip_origem")))
    id_log = cursor.lastrowid

    if result["risk_level"] in ["HIGH", "CRITICAL"]:
        cursor.execute("""
            INSERT INTO ALERTAS (id_log, tipo_alerta, estado_alerta)
            VALUES (?, ?, ?)
        """, (id_log, result["risk_level"], "ACTIVE"))

        # ─── Send Webhooks ───
        try:
            from backend.webhooks import send_webhooks
            webhook_config = get_webhook_config(username)
            if webhook_config:
                email_alert = {
                    "remetente":   data.remetente,
                    "assunto":     data.assunto,
                    "score":       result["final_score"],
                    "nivel_risco": result["risk_level"],
                    "resultado":   result["result"],
                    "data_hora":   ""
                }
                asyncio.create_task(send_webhooks(email_alert, webhook_config))
        except Exception as e:
            print(f"Webhook error: {e}")
        
    if result["risk_level"] in ["HIGH", "CRITICAL"]:
        cursor.execute("""
        INSERT INTO ALERTAS (id_log, tipo_alerta, estado_alerta)
        VALUES (?, ?, ?)
    """, (id_log, result["risk_level"], "ACTIVE"))

    # ─── Send Webhooks ───
  # ─── Send Webhooks ───
    try:
        from backend.webhooks import send_webhooks
        webhook_config = get_webhook_config(username)
        if webhook_config:
            email_alert = {
                "remetente":   data.remetente,
                "assunto":     data.assunto,
                "score":       result["final_score"],
                "nivel_risco": result["risk_level"],
                "resultado":   result["result"],
                "data_hora":   ""
            }
            asyncio.create_task(send_webhooks(email_alert, webhook_config))
    except Exception as e:
        print(f"Webhook error: {e}")

    # ─── Desktop Notification ───
    try:
        from backend.notifications import notify_phishing
        notify_phishing(
            remetente = data.remetente,
            assunto   = data.assunto,
            score     = result["final_score"],
            nivel     = result["risk_level"]
        )
    except Exception as e:
        print(f"Notification error: {e}")

    # ─── WebSocket broadcast ───
    try:
        from backend.main import manager
        asyncio.create_task(manager.broadcast({
            "type":      "phishing_alert",
            "remetente": data.remetente,
            "assunto":   data.assunto,
            "score":     result["final_score"],
            "nivel":     result["risk_level"],
            "resultado": result["result"]
        }))
    except Exception as e:
        print(f"WebSocket broadcast error: {e}")
        
    conn.commit()
    conn.close()

    return ResponseModel(
        success=True,
        message="Email analyzed successfully",
        date={
            "id_email":        id_email,
            "final_score":     result["final_score"],
            "risk_level":      result["risk_level"],
            "result":          result["result"],
            "heuristic_score": result["heuristic_score"],
            "auth_penalty":    result["auth_penalty"],
            "details":         result.get("details", {}),
            "ml_score":        result.get("ml_score", 0),
            "ai_score":        result.get("ai_score", 0),
            "ai_details":      ai_details
        }
    )


# ─────────────────────────────────────────
# IMAP AUTO ANALYZE
# ─────────────────────────────────────────
@router.post("/imap", response_model=ResponseModel)
async def analyze_imap(data: IMAPModel, authorization: Optional[str] = Header(None)):
    username = verify_token(authorization)

    imap_result = fetch_emails(data.email, data.password, data.limit)

    if not imap_result["success"]:
        raise HTTPException(status_code=400, detail=imap_result["error"])

    conn = get_connection()
    cursor = conn.cursor()
    analyzed = []
    skipped  = 0

    webhook_config = get_webhook_config(username)

    for email_data in imap_result["emails"]:

        # ─── Skip duplicates ───
        cursor.execute("""
            SELECT id_email FROM EMAILS
            WHERE remetente = ? AND assunto = ?
            LIMIT 1
        """, (email_data["remetente"], email_data["assunto"]))
        if cursor.fetchone():
            skipped += 1
            continue

        score_result = calculate_score(
            sender=email_data["remetente"],
            subject=email_data["assunto"],
            body=email_data["corpo"],
            spf=email_data["spf"],
            dkim=email_data["dkim"],
            dmarc=email_data["dmarc"]
        )

        cursor.execute("""
            INSERT INTO EMAILS (remetente, assunto, corpo)
            VALUES (?, ?, ?)
        """, (email_data["remetente"], email_data["assunto"], email_data["corpo"]))
        id_email = cursor.lastrowid

        ai_details           = score_result.get("ai_details", {})
        ai_verdict           = ai_details.get("verdict", None)
        ai_conf              = ai_details.get("confidence", None)
        ai_reasons           = str(ai_details.get("reasons", []))
        impersonated_company = ai_details.get("impersonated_company", None)
        official_domain      = ai_details.get("official_domain", None)
        sender_domain        = ai_details.get("sender_domain", None)
        domain_match         = ai_details.get("domain_match", None)

        cursor.execute("""
            INSERT INTO ANALISES (id_email, score, resultado, nivel_risco,
                                  ai_verdict, ai_confidence, ai_reasons,
                                  impersonated_company, official_domain,
                                  sender_domain, domain_match)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (id_email, score_result["final_score"], score_result["result"], score_result["risk_level"],
              ai_verdict, ai_conf, ai_reasons,
              impersonated_company, official_domain, sender_domain,
              1 if domain_match else 0 if domain_match is not None else None))
        id_analise = cursor.lastrowid

        cursor.execute("""
    INSERT INTO LOGS (id_analise, evento, spf, dkim, dmarc, ip_origem)
    VALUES (?, ?, ?, ?, ?, ?)
""", (id_analise, "IMAP auto-analysis", email_data["spf"], email_data["dkim"], email_data["dmarc"], email_data.get("ip_origem")))
        id_log = cursor.lastrowid

        if score_result["risk_level"] in ["HIGH", "CRITICAL"]:
            cursor.execute("""
                INSERT INTO ALERTAS (id_log, tipo_alerta, estado_alerta)
                VALUES (?, ?, ?)
            """, (id_log, score_result["risk_level"], "ACTIVE"))

            # ─── Send Webhooks ───
            try:
                from backend.webhooks import send_webhooks
                if webhook_config:
                    email_alert = {
                        "remetente":   email_data["remetente"],
                        "assunto":     email_data["assunto"],
                        "score":       score_result["final_score"],
                        "nivel_risco": score_result["risk_level"],
                        "resultado":   score_result["result"],
                        "data_hora":   ""
                    }
                    asyncio.create_task(send_webhooks(email_alert, webhook_config))
            except Exception as e:
                print(f"Webhook error: {e}")

            # ─── Desktop Notification ───
            try:
                from backend.notifications import notify_phishing
                notify_phishing(
                    remetente = email_data["remetente"],
                    assunto   = email_data["assunto"],
                    score     = score_result["final_score"],
                    nivel     = score_result["risk_level"]
                )
            except Exception as e:
                print(f"Notification error: {e}")

            # ─── WebSocket broadcast ───
            try:
                from backend.ws_manager import manager
                asyncio.create_task(manager.broadcast({
                    "type":      "phishing_alert",
                    "remetente": email_data["remetente"],
                    "assunto":   email_data["assunto"],
                    "score":     score_result["final_score"],
                    "nivel":     score_result["risk_level"],
                    "resultado": score_result["result"]
                }))
            except Exception as e:
                print(f"WebSocket error: {e}")

    conn.commit()
    conn.close()

    return ResponseModel(
        success=True,
        message=f"{len(analyzed)} emails analyzed, {skipped} skipped (duplicates)",
        date={"analyzed": analyzed, "count": len(analyzed), "skipped": skipped}
    )


# ─────────────────────────────────────────
# GET AI ANALYSIS BY EMAIL ID
# ─────────────────────────────────────────
@router.get("/{id_email}/ai", response_model=ResponseModel)
async def get_ai_analysis(id_email: int, authorization: Optional[str] = Header(None)):
    verify_token(authorization)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT ai_verdict, ai_confidence, ai_reasons,
               score, nivel_risco, resultado,
               impersonated_company, official_domain,
               sender_domain, domain_match
        FROM ANALISES
        WHERE id_email = ?
    """, (id_email,))

    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Analysis not found")

    return ResponseModel(
        success=True,
        message="AI analysis retrieved",
        date={
            "ai_verdict":           row[0],
            "ai_confidence":        row[1],
            "ai_reasons":           row[2],
            "score":                row[3],
            "nivel_risco":          row[4],
            "resultado":            row[5],
            "impersonated_company": row[6],
            "official_domain":      row[7],
            "sender_domain":        row[8],
            "domain_match":         bool(row[9]) if row[9] is not None else None
        }
    )


# ─────────────────────────────────────────
# VIRUSTOTAL URL SCAN
# ─────────────────────────────────────────
@router.get("/{id_email}/virustotal", response_model=ResponseModel)
async def scan_email_urls(id_email: int, authorization: Optional[str] = Header(None)):
    verify_token(authorization)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT corpo FROM EMAILS WHERE id_email = ?", (id_email,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Email not found")

    from backend.virustotal import extract_urls, scan_urls
    urls = extract_urls(row[0] or "")

    if not urls:
        return ResponseModel(
            success=True,
            message="No URLs found in email",
            date={"urls": [], "count": 0}
        )

    results = scan_urls(urls)

    return ResponseModel(
        success=True,
        message=f"{len(results)} URLs analyzed",
        date={"urls": results, "count": len(results)}
    )


# ─────────────────────────────────────────
# SAVE IMAP CREDENTIALS
# ─────────────────────────────────────────
@router.post("/imap/credentials", response_model=ResponseModel)
async def save_imap_credentials(data: dict, authorization: Optional[str] = Header(None)):
    username = verify_token(authorization)

    from utils.crypto import encrypt
    from datetime import datetime

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id_user FROM USERS WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    id_user        = user[0]
    encrypted_pass = encrypt(data.get("password", ""))
    interval       = data.get("interval", 30)
    auto_check     = data.get("auto_check", 1)

    cursor.execute("SELECT id_cred FROM IMAP_CREDENTIALS WHERE id_user = ?", (id_user,))
    existing = cursor.fetchone()

    if existing:
        cursor.execute("""
            UPDATE IMAP_CREDENTIALS
            SET email = ?, password = ?, auto_check = ?, interval = ?, last_check = ?
            WHERE id_user = ?
        """, (data.get("email"), encrypted_pass, auto_check, interval,
              datetime.now().isoformat(), id_user))
    else:
        cursor.execute("""
            INSERT INTO IMAP_CREDENTIALS (id_user, email, password, auto_check, interval, last_check)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (id_user, data.get("email"), encrypted_pass, auto_check, interval,
              datetime.now().isoformat()))

    conn.commit()
    conn.close()

    return ResponseModel(
        success=True,
        message="IMAP credentials saved",
        date={"email": data.get("email")}
    )


# ─────────────────────────────────────────
# LOAD IMAP CREDENTIALS
# ─────────────────────────────────────────
@router.get("/imap/credentials", response_model=ResponseModel)
async def load_imap_credentials(authorization: Optional[str] = Header(None)):
    username = verify_token(authorization)

    from utils.crypto import decrypt

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id_user FROM USERS WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return ResponseModel(success=False, message="User not found")

    cursor.execute("""
        SELECT email, password, auto_check, interval, last_check
        FROM IMAP_CREDENTIALS WHERE id_user = ?
    """, (user[0],))

    row = cursor.fetchone()
    conn.close()

    if not row:
        return ResponseModel(success=False, message="No credentials saved")

    try:
        decrypted_pass = decrypt(row[1])
    except:
        decrypted_pass = ""

    return ResponseModel(
        success=True,
        message="Credentials loaded",
        date={
            "email":      row[0],
            "password":   decrypted_pass,
            "auto_check": bool(row[2]),
            "interval":   row[3],
            "last_check": row[4]
        }
    )


# ─────────────────────────────────────────
# TOGGLE AUTOCHECK
# ─────────────────────────────────────────
@router.post("/imap/autocheck", response_model=ResponseModel)
async def toggle_autocheck(data: dict, authorization: Optional[str] = Header(None)):
    username = verify_token(authorization)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id_user FROM USERS WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    cursor.execute("""
        UPDATE IMAP_CREDENTIALS SET auto_check = ?
        WHERE id_user = ?
    """, (1 if data.get("enabled") else 0, user[0]))

    conn.commit()
    conn.close()

    return ResponseModel(success=True, message="Auto check updated")


# ─────────────────────────────────────────
# GET ALL EMAILS
# ─────────────────────────────────────────
@router.get("/", response_model=ResponseModel)
async def get_emails(authorization: Optional[str] = Header(None)):
    verify_token(authorization)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT EMAILS.id_email, EMAILS.remetente, EMAILS.assunto,
               EMAILS.data_hora, ANALISES.score,
               ANALISES.nivel_risco, ANALISES.resultado
        FROM EMAILS
        JOIN ANALISES ON EMAILS.id_email = ANALISES.id_email
        ORDER BY EMAILS.data_hora DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    emails = [
        {
            "id_email":    row[0],
            "remetente":   row[1],
            "assunto":     row[2],
            "data_hora":   row[3],
            "score":       row[4],
            "nivel_risco": row[5],
            "resultado":   row[6]
        }
        for row in rows
    ]

    return ResponseModel(
        success=True,
        message="Emails retrieved",
        date={"emails": emails}
    )


# ─────────────────────────────────────────
# GET EMAIL BY ID
# ─────────────────────────────────────────
@router.get("/{id_email}", response_model=ResponseModel)
async def get_email(id_email: int, authorization: Optional[str] = Header(None)):
    verify_token(authorization)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT EMAILS.id_email, EMAILS.remetente, EMAILS.assunto,
               EMAILS.corpo, EMAILS.data_hora, ANALISES.score,
               ANALISES.nivel_risco, ANALISES.resultado,
               LOGS.spf, LOGS.dkim, LOGS.dmarc
        FROM EMAILS
        JOIN ANALISES ON EMAILS.id_email = ANALISES.id_email
        LEFT JOIN LOGS ON ANALISES.id_analise = LOGS.id_analise
        WHERE EMAILS.id_email = ?
    """, (id_email,))

    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Email not found")

    return ResponseModel(
        success=True,
        message="Email retrieved",
        date={
            "id_email":    row[0],
            "remetente":   row[1],
            "assunto":     row[2],
            "corpo":       row[3],
            "data_hora":   row[4],
            "score":       row[5],
            "nivel_risco": row[6],
            "resultado":   row[7],
            "spf":         row[8],
            "dkim":        row[9],
            "dmarc":       row[10]
        }
    )