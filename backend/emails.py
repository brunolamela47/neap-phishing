# backend/emails.py

# ─────────────────────────────────────────
# NEAP — Network Email Anti-Phishing
# Email Analysis Endpoints
# ─────────────────────────────────────────

from fastapi import APIRouter, HTTPException, Header
from typing import Optional
import sys
import os

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


# ─────────────────────────────────────────
# ANALYZE EMAIL
# ─────────────────────────────────────────
@router.post("/analyze", response_model=ResponseModel)
async def analyze_email(data: EmailAnalyzeModel, authorization: Optional[str] = Header(None)):
    verify_token(authorization)

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
        INSERT INTO LOGS (id_analise, evento, spf, dkim, dmarc)
        VALUES (?, ?, ?, ?, ?)
    """, (id_analise, "Email analyzed", data.spf, data.dkim, data.dmarc))
    id_log = cursor.lastrowid

    if result["risk_level"] in ["HIGH", "CRITICAL"]:
        cursor.execute("""
            INSERT INTO ALERTAS (id_log, tipo_alerta, estado_alerta)
            VALUES (?, ?, ?)
        """, (id_log, result["risk_level"], "ACTIVE"))

    conn.commit()
    conn.close()

    return ResponseModel(
        success=True,
        message="Email analyzed successfully",
        date={
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
    verify_token(authorization)

    imap_result = fetch_emails(data.email, data.password, data.limit)

    if not imap_result["success"]:
        raise HTTPException(status_code=400, detail=imap_result["error"])

    conn = get_connection()
    cursor = conn.cursor()
    analyzed = []

    for email_data in imap_result["emails"]:
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
            INSERT INTO LOGS (id_analise, evento, spf, dkim, dmarc)
            VALUES (?, ?, ?, ?, ?)
        """, (id_analise, "IMAP auto-analysis", email_data["spf"], email_data["dkim"], email_data["dmarc"]))
        id_log = cursor.lastrowid

        if score_result["risk_level"] in ["HIGH", "CRITICAL"]:
            cursor.execute("""
                INSERT INTO ALERTAS (id_log, tipo_alerta, estado_alerta)
                VALUES (?, ?, ?)
            """, (id_log, score_result["risk_level"], "ACTIVE"))

        analyzed.append({
            "remetente":  email_data["remetente"],
            "assunto":    email_data["assunto"],
            "score":      score_result["final_score"],
            "risk_level": score_result["risk_level"],
            "result":     score_result["result"]
        })

    conn.commit()
    conn.close()

    return ResponseModel(
        success=True,
        message=f"{len(analyzed)} emails analyzed",
        date={"analyzed": analyzed, "count": len(analyzed)}
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
            "ai_verdict":          row[0],
            "ai_confidence":       row[1],
            "ai_reasons":          row[2],
            "score":               row[3],
            "nivel_risco":         row[4],
            "resultado":           row[5],
            "impersonated_company": row[6],
            "official_domain":     row[7],
            "sender_domain":       row[8],
            "domain_match":        bool(row[9]) if row[9] is not None else None
        }
    )


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