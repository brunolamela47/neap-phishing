

from fastapi import APIRouter, HTTPException, Header
from typing import Optional
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.database import get_connection

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
# STATS
# ─────────────────────────────────────────
@router.get("/stats")
async def get_stats(authorization: Optional[str] = Header(None)):
    verify_token(authorization)
    conn = get_connection()
    cursor = conn.cursor()

    # Total emails
    cursor.execute("SELECT COUNT(*) FROM EMAILS")
    total_emails = cursor.fetchone()[0]

    # Total phishing
    cursor.execute("SELECT COUNT(*) FROM ANALISES WHERE resultado = 'PHISHING'")
    total_phishing = cursor.fetchone()[0]

    # Total legitimate
    cursor.execute("SELECT COUNT(*) FROM ANALISES WHERE resultado = 'LEGITIMATE'")
    total_legit = cursor.fetchone()[0]

    # Average score
    cursor.execute("SELECT AVG(score) FROM ANALISES")
    avg = cursor.fetchone()[0]
    avg_score = round(avg) if avg else 0

    # Total alerts
    cursor.execute("SELECT COUNT(*) FROM ALERTAS WHERE estado_alerta = 'ACTIVE'")
    total_alerts = cursor.fetchone()[0]

    # Recent emails — JOIN
    cursor.execute("""
        SELECT EMAILS.remetente, EMAILS.assunto, EMAILS.data_hora,
               ANALISES.score, ANALISES.nivel_risco, ANALISES.resultado
        FROM EMAILS
        JOIN ANALISES ON EMAILS.id_email = ANALISES.id_email
        ORDER BY EMAILS.data_hora DESC
        LIMIT 10
    """)

    rows = cursor.fetchall()
    recent_emails = [
        {
            "remetente":  row[0],
            "assunto":    row[1],
            "data_hora":  row[2],
            "score":      row[3],
            "nivel_risco": row[4],
            "resultado":  row[5]
        }
        for row in rows
    ]

    conn.close()

    return {
        "success": True,
        "date": {
            "total_emails":   total_emails,
            "total_phishing": total_phishing,
            "total_legit":    total_legit,
            "avg_score":      avg_score,
            "total_alerts":   total_alerts,
            "recent_emails":  recent_emails
        }
    }


# ─────────────────────────────────────────
# CHART DATA
# ─────────────────────────────────────────
@router.get("/chart")
async def get_chart(period: str = "7d", authorization: Optional[str] = Header(None)):
    verify_token(authorization)
    conn = get_connection()
    cursor = conn.cursor()

    days = 7 if period == "7d" else 30

    cursor.execute(f"""
        SELECT DATE(EMAILS.data_hora) as dia,
               SUM(CASE WHEN ANALISES.resultado = 'PHISHING' THEN 1 ELSE 0 END) as phishing,
               SUM(CASE WHEN ANALISES.resultado = 'LEGITIMATE' THEN 1 ELSE 0 END) as legitimate
        FROM EMAILS
        JOIN ANALISES ON EMAILS.id_email = ANALISES.id_email
        WHERE EMAILS.data_hora >= DATE('now', '-{days} days')
        GROUP BY dia
        ORDER BY dia ASC
    """)

    rows = cursor.fetchall()
    conn.close()

    labels     = [row[0] for row in rows]
    phishing   = [row[1] for row in rows]
    legitimate = [row[2] for row in rows]

    return {
        "success": True,
        "date": {
            "labels":     labels,
            "phishing":   phishing,
            "legitimate": legitimate
        }
    }


# ─────────────────────────────────────────
# EXPORT
# ─────────────────────────────────────────
@router.get("/export")
async def export_logs(format: str = "csv", authorization: Optional[str] = Header(None)):
    verify_token(authorization)
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT EMAILS.remetente, EMAILS.assunto, EMAILS.data_hora,
               ANALISES.score, ANALISES.nivel_risco, ANALISES.resultado,
               LOGS.spf, LOGS.dkim, LOGS.dmarc, LOGS.ip_origem
        FROM EMAILS
        JOIN ANALISES ON EMAILS.id_email = ANALISES.id_email
        LEFT JOIN LOGS ON ANALISES.id_analise = LOGS.id_analise
        ORDER BY EMAILS.data_hora DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    if format == "csv":
        from fastapi.responses import StreamingResponse
        import io
        import csv

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Sender","Subject","Date","Score","Risk","Result","SPF","DKIM","DMARC","IP"])
        writer.writerows(rows)
        output.seek(0)

        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=neap-logs.csv"}
        )

    raise HTTPException(status_code=400, detail="Format not supported yet")

# Adiciona estes endpoints ao backend/dashboard.py

# ─────────────────────────────────────────
# LOGS
# ─────────────────────────────────────────
@router.get("/logs")
async def get_logs(authorization: Optional[str] = Header(None)):
    verify_token(authorization)
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id_log, id_analise, data_hora, evento, ip_origem, spf, dkim, dmarc
        FROM LOGS
        ORDER BY data_hora DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    logs = [
        {
            "id_log":     row[0],
            "id_analise": row[1],
            "data_hora":  row[2],
            "evento":     row[3],
            "ip_origem":  row[4],
            "spf":        row[5],
            "dkim":       row[6],
            "dmarc":      row[7]
        }
        for row in rows
    ]

    return {"success": True, "date": {"logs": logs}}


# ─────────────────────────────────────────
# ALERTS
# ─────────────────────────────────────────
@router.get("/alerts")
async def get_alerts(authorization: Optional[str] = Header(None)):
    verify_token(authorization)
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id_alerta, id_log, tipo_alerta, estado_alerta,
               datetime('now') as data_hora
        FROM ALERTAS
        ORDER BY id_alerta DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    alerts = [
        {
            "id_alerta":    row[0],
            "id_log":       row[1],
            "tipo_alerta":  row[2],
            "estado_alerta": row[3],
            "data_hora":    row[4]
        }
        for row in rows
    ]

    return {"success": True, "date": {"alerts": alerts}}


# ─────────────────────────────────────────
# RESOLVE ALERT
# ─────────────────────────────────────────
@router.post("/alerts/{id_alerta}/resolve")
async def resolve_alert(id_alerta: int, authorization: Optional[str] = Header(None)):
    verify_token(authorization)
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE ALERTAS SET estado_alerta = 'RESOLVED'
        WHERE id_alerta = ?
    """, (id_alerta,))

    conn.commit()
    conn.close()

    return {"success": True, "message": "Alert resolved"}


# ─────────────────────────────────────────
# RESOLVE ALL ALERTS
# ─────────────────────────────────────────
@router.post("/alerts/resolve-all")
async def resolve_all_alerts(authorization: Optional[str] = Header(None)):
    verify_token(authorization)
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE ALERTAS SET estado_alerta = 'RESOLVED'
        WHERE estado_alerta = 'ACTIVE'
    """)

    conn.commit()
    conn.close()

    return {"success": True, "message": "All alerts resolved"}