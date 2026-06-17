# backend/webhooks.py

# ─────────────────────────────────────────
# NEAP — Network Email Anti-Phishing
# Webhooks — Discord, Slack, Telegram
# ─────────────────────────────────────────

import httpx
import json

# ─── Discord ───
async def send_discord(webhook_url: str, email_data: dict) -> bool:
    """Send phishing alert to Discord webhook."""
    try:
        score      = email_data.get("score", 0)
        remetente  = email_data.get("remetente", "—")
        assunto    = email_data.get("assunto", "—")
        nivel      = email_data.get("nivel_risco", "—")
        resultado  = email_data.get("resultado", "—")

        color = 0xFF0000 if nivel == "CRITICAL" else 0xFF6600 if nivel == "HIGH" else 0xFFAA00

        payload = {
            "username": "NEAP Security",
            "avatar_url": "https://i.imgur.com/4M34hi2.png",
            "embeds": [{
                "title": f"🚨 Phishing Detetado — {nivel}",
                "color": color,
                "fields": [
                    {"name": "📧 Remetente",  "value": f"`{remetente}`",  "inline": True},
                    {"name": "📊 Score",       "value": f"`{score}/100`",  "inline": True},
                    {"name": "⚠️ Risco",       "value": f"`{nivel}`",      "inline": True},
                    {"name": "📨 Assunto",     "value": f"{assunto[:100]}", "inline": False},
                    {"name": "🔍 Resultado",   "value": f"`{resultado}`",  "inline": True},
                ],
                "footer": {"text": "NEAP — Network Email Anti-Phishing · ISTEC Porto"},
                "timestamp": email_data.get("data_hora", "")
            }]
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(webhook_url, json=payload, timeout=10)
            return response.status_code in [200, 204]

    except Exception as e:
        print(f"Discord webhook error: {e}")
        return False


# ─── Slack ───
async def send_slack(webhook_url: str, email_data: dict) -> bool:
    """Send phishing alert to Slack webhook."""
    try:
        score     = email_data.get("score", 0)
        remetente = email_data.get("remetente", "—")
        assunto   = email_data.get("assunto", "—")
        nivel     = email_data.get("nivel_risco", "—")
        resultado = email_data.get("resultado", "—")

        emoji = "🔴" if nivel == "CRITICAL" else "🟠" if nivel == "HIGH" else "🟡"

        payload = {
            "text": f"{emoji} *Phishing Detetado — {nivel}*",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"🚨 NEAP Alert — {nivel}"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Remetente:*\n`{remetente}`"},
                        {"type": "mrkdwn", "text": f"*Score:*\n`{score}/100`"},
                        {"type": "mrkdwn", "text": f"*Assunto:*\n{assunto[:100]}"},
                        {"type": "mrkdwn", "text": f"*Resultado:*\n`{resultado}`"},
                    ]
                },
                {
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": "NEAP — Network Email Anti-Phishing · ISTEC Porto"}]
                }
            ]
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(webhook_url, json=payload, timeout=10)
            return response.status_code == 200

    except Exception as e:
        print(f"Slack webhook error: {e}")
        return False


# ─── Telegram ───
async def send_telegram(bot_token: str, chat_id: str, email_data: dict) -> bool:
    """Send phishing alert to Telegram bot."""
    try:
        score     = email_data.get("score", 0)
        remetente = email_data.get("remetente", "—")
        assunto   = email_data.get("assunto", "—")
        nivel     = email_data.get("nivel_risco", "—")
        resultado = email_data.get("resultado", "—")

        emoji = "🔴" if nivel == "CRITICAL" else "🟠" if nivel == "HIGH" else "🟡"

        message = f"""🚨 *NEAP Alert — Phishing Detetado*

{emoji} *Nível:* `{nivel}`
📊 *Score:* `{score}/100`
📧 *Remetente:* `{remetente}`
📨 *Assunto:* {assunto[:100]}
🔍 *Resultado:* `{resultado}`

_NEAP — Network Email Anti-Phishing · ISTEC Porto_"""

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

        async with httpx.AsyncClient() as client:
            response = await client.post(url, json={
                "chat_id":    chat_id,
                "text":       message,
                "parse_mode": "Markdown"
            }, timeout=10)
            return response.status_code == 200

    except Exception as e:
        print(f"Telegram webhook error: {e}")
        return False


# ─── Send all configured webhooks ───
async def send_webhooks(email_data: dict, webhook_config: dict):
    """Send alert to all configured webhooks."""
    results = {}

    if webhook_config.get("discord_url"):
        results["discord"] = await send_discord(webhook_config["discord_url"], email_data)

    if webhook_config.get("slack_url"):
        results["slack"] = await send_slack(webhook_config["slack_url"], email_data)

    if webhook_config.get("telegram_token") and webhook_config.get("telegram_chat_id"):
        results["telegram"] = await send_telegram(
            webhook_config["telegram_token"],
            webhook_config["telegram_chat_id"],
            email_data
        )

    return results