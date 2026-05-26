

from fastapi import APIRouter, HTTPException, Header
from typing import Optional
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.models import EmailAnalyzeModel, ResponseModel
from database.database import get_connection
from utils.score import calculate_score

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

    # Run score engine
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

    # Insert email
    cursor.execute("""
        INSERT INTO EMAILS (remetente, assunto, corpo)
        VALUES (?, ?, ?)
    """, (data.remetente, data.assunto, data.corpo))
    id_email = cursor.lastrowid

    # Insert analysis
    cursor.execute("""
        INSERT INTO ANALISES (id_email, score, resultado, nivel_risco)
        VALUES (?, ?, ?, ?)
    """, (id_email, result["final_score"], result["result"], result["risk_level"]))
    id_analise = cursor.lastrowid

    # Insert log
    cursor.execute("""
        INSERT INTO LOGS (id_analise, evento, spf, dkim, dmarc)
        VALUES (?, ?, ?, ?, ?)
    """, (id_analise, "Email analyzed", data.spf, data.dkim, data.dmarc))
    id_log = cursor.lastrowid

    # Insert alert if high risk
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
            "final_score":  result["final_score"],
            "risk_level":   result["risk_level"],
            "result":       result["result"],
            "heuristic_score": result["heuristic_score"],
            "auth_penalty": result["auth_penalty"],
            "details":      result["details"]
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
            "id_email":   row[0],
            "remetente":  row[1],
            "assunto":    row[2],
            "data_hora":  row[3],
            "score":      row[4],
            "nivel_risco": row[5],
            "resultado":  row[6]
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
            "id_email":   row[0],
            "remetente":  row[1],
            "assunto":    row[2],
            "corpo":      row[3],
            "data_hora":  row[4],
            "score":      row[5],
            "nivel_risco": row[6],
            "resultado":  row[7],
            "spf":        row[8],
            "dkim":       row[9],
            "dmarc":      row[10]
        }
    )
