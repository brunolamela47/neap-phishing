

from fastapi import APIRouter, HTTPException, Header
from typing import Optional
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.webhooks import send_webhooks

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
# SAVE WEBHOOK SETTINGS
# ─────────────────────────────────────────
@router.post("/webhooks")
async def save_webhooks(data: dict, authorization: Optional[str] = Header(None)):
    username = verify_token(authorization)
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id_user FROM USERS WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    id_user = user[0]

    cursor.execute("SELECT id_webhook FROM WEBHOOK_SETTINGS WHERE id_user = ?", (id_user,))
    existing = cursor.fetchone()

    if existing:
        cursor.execute("""
            UPDATE WEBHOOK_SETTINGS
            SET discord_url = ?, slack_url = ?, telegram_token = ?, telegram_chat_id = ?, active = ?
            WHERE id_user = ?
        """, (
            data.get("discord_url"),
            data.get("slack_url"),
            data.get("telegram_token"),
            data.get("telegram_chat_id"),
            1,
            id_user
        ))
    else:
        cursor.execute("""
            INSERT INTO WEBHOOK_SETTINGS (id_user, discord_url, slack_url, telegram_token, telegram_chat_id)
            VALUES (?, ?, ?, ?, ?)
        """, (
            id_user,
            data.get("discord_url"),
            data.get("slack_url"),
            data.get("telegram_token"),
            data.get("telegram_chat_id")
        ))

    conn.commit()
    conn.close()

    return {"success": True, "message": "Webhooks guardados"}


# ─────────────────────────────────────────
# LOAD WEBHOOK SETTINGS
# ─────────────────────────────────────────
@router.get("/webhooks")
async def load_webhooks(authorization: Optional[str] = Header(None)):
    username = verify_token(authorization)
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id_user FROM USERS WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return {"success": False}

    cursor.execute("""
        SELECT discord_url, slack_url, telegram_token, telegram_chat_id, active
        FROM WEBHOOK_SETTINGS WHERE id_user = ?
    """, (user[0],))

    row = cursor.fetchone()
    conn.close()

    if not row:
        return {"success": False, "date": {}}

    return {"success": True, "date": {
        "discord_url":       row[0],
        "slack_url":         row[1],
        "telegram_token":    row[2],
        "telegram_chat_id":  row[3],
        "active":            bool(row[4])
    }}


# ─────────────────────────────────────────
# TEST WEBHOOK
# ─────────────────────────────────────────
@router.post("/webhooks/test")
async def test_webhook(data: dict, authorization: Optional[str] = Header(None)):
    verify_token(authorization)

    test_email = {
        "remetente":  "seguranca@caixageral-bancos.tk",
        "assunto":    "URGENTE: Conta bloqueada — Teste NEAP",
        "score":      95,
        "nivel_risco": "CRITICAL",
        "resultado":  "PHISHING",
        "data_hora":  ""
    }

    results = await send_webhooks(test_email, data)
    return {"success": True, "results": results}


# ─────────────────────────────────────────
# ATTACK MAP DATA
# ─────────────────────────────────────────
@router.get("/map")
async def get_attack_map(authorization: Optional[str] = Header(None)):
    verify_token(authorization)
    conn = get_connection()
    cursor = conn.cursor()

    # Get all phishing emails with IP
    cursor.execute("""
        SELECT LOGS.ip_origem, COUNT(*) as total,
               ANALISES.nivel_risco
        FROM LOGS
        JOIN ANALISES ON LOGS.id_analise = ANALISES.id_analise
        WHERE LOGS.ip_origem IS NOT NULL
        AND ANALISES.nivel_risco IN ('HIGH', 'CRITICAL')
        GROUP BY LOGS.ip_origem
        ORDER BY total DESC
        LIMIT 50
    """)

    rows = cursor.fetchall()
    conn.close()

    from backend.geoip import geolocate_ip
    attacks = []

    for row in rows:
        ip    = row[0]
        count = row[1]
        nivel = row[2]

        geo = geolocate_ip(ip)
        if geo.get("lat") and geo.get("lon"):
            attacks.append({
                "ip":      ip,
                "count":   count,
                "nivel":   nivel,
                "country": geo.get("country"),
                "city":    geo.get("city"),
                "lat":     geo.get("lat"),
                "lon":     geo.get("lon"),
                "isp":     geo.get("isp")
            })

    return {"success": True, "date": {"attacks": attacks}}

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
    cursor.execute("""
    SELECT COUNT(*) FROM ANALISES 
    WHERE resultado IN ('PHISHING', 'LIKELY PHISHING', 'SUSPICIOUS')
""")
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

    trend_phishing = "+0%"
    trend_legit    = "+0%"
    trend_total    = f"+{total_emails}"

    if total_emails > 0:
        phishing_pct   = round((total_phishing / total_emails) * 100)
        legit_pct      = round((total_legit / total_emails) * 100)
        trend_phishing = f"+{phishing_pct}%"
        trend_legit    = f"+{legit_pct}%"

    conn.close()

    return {
        "success": True,
        "date": {
            "total_emails":   total_emails,
            "total_phishing": total_phishing,
            "total_legit":    total_legit,
            "avg_score":      avg_score,
            "total_alerts":   total_alerts,
            "recent_emails":  recent_emails,
            "trend_total":    trend_total,
            "trend_phishing": trend_phishing,
            "trend_legit":    trend_legit,
        }
    }


# ─────────────────────────────────────────
# BLOCK SENDER
# ─────────────────────────────────────────
@router.post("/alerts/{id_alerta}/block")
async def block_sender(id_alerta: int, authorization: Optional[str] = Header(None)):
    verify_token(authorization)
    conn = get_connection()
    cursor = conn.cursor()

    # Get sender from alert → log → analysis → email
    cursor.execute("""
        SELECT EMAILS.remetente
        FROM ALERTAS
        JOIN LOGS ON ALERTAS.id_log = LOGS.id_log
        JOIN ANALISES ON LOGS.id_analise = ANALISES.id_analise
        JOIN EMAILS ON ANALISES.id_email = EMAILS.id_email
        WHERE ALERTAS.id_alerta = ?
    """, (id_alerta,))

    row = cursor.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")

    sender = row[0]

    # Insert into blocked senders
    try:
        cursor.execute("""
            INSERT INTO BLOCKED_SENDERS (sender, reason)
            VALUES (?, ?)
        """, (sender, "Blocked from alert"))
    except:
        pass  # Already blocked

    # Resolve the alert
    cursor.execute("""
        UPDATE ALERTAS SET estado_alerta = 'RESOLVED'
        WHERE id_alerta = ?
    """, (id_alerta,))

    conn.commit()
    conn.close()

    return {"success": True, "message": f"Sender {sender} blocked", "sender": sender}


# ─────────────────────────────────────────
# GET BLOCKED SENDERS
# ─────────────────────────────────────────
@router.get("/blocked")
async def get_blocked(authorization: Optional[str] = Header(None)):
    verify_token(authorization)
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id_blocked, sender, blocked_at, reason
        FROM BLOCKED_SENDERS
        ORDER BY blocked_at DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    blocked = [
        {
            "id_blocked": row[0],
            "sender":     row[1],
            "blocked_at": row[2],
            "reason":     row[3]
        }
        for row in rows
    ]

    return {"success": True, "date": {"blocked": blocked}}


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

    # Stats
    cursor.execute("SELECT COUNT(*) FROM EMAILS")
    total_emails = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM ANALISES WHERE resultado IN ('PHISHING', 'LIKELY PHISHING')")
    total_phishing = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM ANALISES WHERE resultado = 'LEGITIMATE'")
    total_legit = cursor.fetchone()[0]

    cursor.execute("SELECT AVG(score) FROM ANALISES")
    avg = cursor.fetchone()[0]
    avg_score = round(avg) if avg else 0

    conn.close()

    # ─── CSV ───
    if format == "csv":
        from fastapi.responses import StreamingResponse
        import io
        import csv

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Remetente", "Assunto", "Data", "Score", "Risco", "Resultado", "SPF", "DKIM", "DMARC", "IP"])
        writer.writerows(rows)
        output.seek(0)

        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=neap-relatorio.csv"}
        )

    # ─── PDF ───
    if format == "pdf":
        from fastapi.responses import StreamingResponse
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from datetime import datetime
        import io

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm
        )

        styles = getSampleStyleSheet()
        elements = []

        # ─── Title ───
        title_style = ParagraphStyle(
            'Title',
            parent=styles['Title'],
            fontSize=22,
            textColor=colors.HexColor('#6366f1'),
            spaceAfter=6,
            alignment=TA_CENTER
        )

        subtitle_style = ParagraphStyle(
            'Subtitle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#6b6b6b'),
            spaceAfter=4,
            alignment=TA_CENTER
        )

        normal_style = ParagraphStyle(
            'Normal',
            parent=styles['Normal'],
            fontSize=9,
            textColor=colors.HexColor('#0f0f0f'),
        )

        elements.append(Paragraph("NEAP", title_style))
        elements.append(Paragraph("Network Email Anti-Phishing", subtitle_style))
        elements.append(Paragraph(f"Relatório gerado em {datetime.now().strftime('%d/%m/%Y às %H:%M')}", subtitle_style))
        elements.append(Spacer(1, 0.5*cm))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e5e5e5')))
        elements.append(Spacer(1, 0.5*cm))

        # ─── Stats ───
        elements.append(Paragraph("Resumo Executivo", ParagraphStyle('H2', parent=styles['Heading2'], fontSize=13, textColor=colors.HexColor('#0f0f0f'), spaceAfter=8)))

        stats_data = [
            ["Métrica", "Valor"],
            ["Total de Emails Analisados", str(total_emails)],
            ["Emails de Phishing Detetados", str(total_phishing)],
            ["Emails Legítimos", str(total_legit)],
            ["Score Médio de Risco", str(avg_score)],
            ["Taxa de Phishing", f"{round((total_phishing/total_emails)*100) if total_emails > 0 else 0}%"],
        ]

        stats_table = Table(stats_data, colWidths=[10*cm, 6*cm])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND',   (0, 0), (-1, 0), colors.HexColor('#6366f1')),
            ('TEXTCOLOR',    (0, 0), (-1, 0), colors.white),
            ('FONTNAME',     (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE',     (0, 0), (-1, 0), 10),
            ('ALIGN',        (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME',     (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE',     (0, 1), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f9f9f9'), colors.white]),
            ('GRID',         (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e5e5')),
            ('TOPPADDING',   (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING',(0, 0), (-1, -1), 6),
            ('LEFTPADDING',  (0, 0), (-1, -1), 8),
        ]))

        elements.append(stats_table)
        elements.append(Spacer(1, 0.8*cm))

        # ─── Email Table ───
        elements.append(Paragraph("Detalhes dos Emails Analisados", ParagraphStyle('H2', parent=styles['Heading2'], fontSize=13, textColor=colors.HexColor('#0f0f0f'), spaceAfter=8)))

        table_data = [["#", "Remetente", "Assunto", "Score", "Risco", "Resultado", "SPF", "DKIM"]]

        for i, row in enumerate(rows, 1):
            table_data.append([
                str(i),
                str(row[0])[:30] + "..." if len(str(row[0])) > 30 else str(row[0]),
                str(row[1])[:35] + "..." if len(str(row[1])) > 35 else str(row[1]),
                str(row[3]),
                str(row[4]) or "-",
                str(row[5]),
                str(row[6]) or "NONE",
                str(row[7]) or "NONE",
            ])

        col_widths = [1*cm, 4.5*cm, 5*cm, 1.5*cm, 2*cm, 2.5*cm, 1.5*cm, 1.5*cm]
        email_table = Table(table_data, colWidths=col_widths, repeatRows=1)

        email_table.setStyle(TableStyle([
            ('BACKGROUND',   (0, 0), (-1, 0), colors.HexColor('#6366f1')),
            ('TEXTCOLOR',    (0, 0), (-1, 0), colors.white),
            ('FONTNAME',     (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE',     (0, 0), (-1, 0), 8),
            ('ALIGN',        (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME',     (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE',     (0, 1), (-1, -1), 7),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f9f9f9'), colors.white]),
            ('GRID',         (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e5e5')),
            ('TOPPADDING',   (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING',(0, 0), (-1, -1), 4),
            ('LEFTPADDING',  (0, 0), (-1, -1), 4),
        ]))

        elements.append(email_table)
        elements.append(Spacer(1, 0.8*cm))

        # ─── Footer ───
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e5e5e5')))
        elements.append(Spacer(1, 0.3*cm))
        elements.append(Paragraph(
            "NEAP — Network Email Anti-Phishing · CTeSP Cibersegurança · ISTEC Porto · 2025/2027",
            ParagraphStyle('Footer', parent=styles['Normal'], fontSize=7, textColor=colors.HexColor('#a0a0a0'), alignment=TA_CENTER)
        ))

        doc.build(elements)
        buffer.seek(0)

        return StreamingResponse(
            buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=neap-relatorio.pdf"}
        )

    raise HTTPException(status_code=400, detail="Formato não suportado")

# ─────────────────────────────────────────
# UNBLOCK SENDER
# ─────────────────────────────────────────
@router.delete("/blocked/{id_blocked}")
async def unblock_sender(id_blocked: int, authorization: Optional[str] = Header(None)):
    verify_token(authorization)
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM BLOCKED_SENDERS WHERE id_blocked = ?", (id_blocked,))
    conn.commit()
    conn.close()

    return {"success": True, "message": "Sender unblocked"}

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

@router.get("/export/save")
async def save_export(format: str = "pdf", authorization: Optional[str] = Header(None)):
    import os
    from datetime import datetime

    verify_token(authorization)

    try:
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        filename = f"neap-relatorio-{datetime.now().strftime('%Y%m%d-%H%M%S')}.{format}"
        filepath = os.path.join(desktop, filename)

        print(f"DEBUG desktop: {desktop}")
        print(f"DEBUG filepath: {filepath}")

        # Generate content
        response = await export_logs(format=format, authorization=authorization)

        print(f"DEBUG response type: {type(response)}")

        # Read response body
        body = b""
        async for chunk in response.body_iterator:
            body += chunk

        print(f"DEBUG body size: {len(body)}")

        with open(filepath, 'wb') as f:
            f.write(body)

        return {"success": True, "message": f"Ficheiro guardado!", "path": filepath}

    except Exception as e:
        print(f"DEBUG error: {e}")
        return {"success": False, "message": str(e)}
# ─────────────────────────────────────────
# EXPORT
# ─────────────────────────────────────────


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