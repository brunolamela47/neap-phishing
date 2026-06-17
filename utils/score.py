# utils/score.py

# ─────────────────────────────────────────
# NEAP — Network Email Anti-Phishing
# Phishing Score Engine
# ─────────────────────────────────────────

import sys
import os
import re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.heuristic import run_heuristic_analysis, is_trusted_sender

# ─── Try load ML model ───
try:
    from ml.model import predict as ml_predict
    ML_AVAILABLE = True
except:
    ML_AVAILABLE = False

# ─── Try load AI ───
try:
    from backend.ollama_ai import analyze_with_ai
    AI_AVAILABLE = True
except:
    AI_AVAILABLE = False

RISK_LEVELS = [
    (86, 100, {"level": "CRITICAL", "result": "PHISHING",        "emoji": "[CRITICAL]"}),
    (61, 85,  {"level": "HIGH",     "result": "LIKELY PHISHING", "emoji": "[HIGH]"}),
    (31, 60,  {"level": "MEDIUM",   "result": "SUSPICIOUS",      "emoji": "[MEDIUM]"}),
    (0,  30,  {"level": "LOW",      "result": "LEGITIMATE",      "emoji": "[LOW]"}),
]


def get_risk_level(score: int) -> dict:
    for (min_score, max_score, risk) in RISK_LEVELS:
        if min_score <= score <= max_score:
            return risk
    return {"level": "UNKNOWN", "result": "UNKNOWN", "emoji": "[UNKNOWN]"}


def is_blocked_sender(sender: str) -> bool:
    """Check if sender is in blocked list."""
    try:
        from database.database import get_connection
        conn = get_connection()
        cursor = conn.cursor()

        # Extract email from "Name <email@domain.com>" format
        email_match = re.search(r'<(.+?)>', sender)
        sender_email = email_match.group(1) if email_match else sender.strip()

        cursor.execute("""
            SELECT id_blocked FROM BLOCKED_SENDERS
            WHERE sender = ? OR sender LIKE ?
        """, (sender_email, f"%{sender_email}%"))

        result = cursor.fetchone()
        conn.close()
        return result is not None
    except Exception as e:
        print(f"is_blocked_sender error: {e}")
        return False


def calculate_score(sender: str, subject: str, body: str,
                    spf: str = "NONE", dkim: str = "NONE", dmarc: str = "NONE") -> dict:

    try:
        # ─── Check if sender is blocked FIRST ───
        if is_blocked_sender(sender):
            print(f"BLOCKED sender detected: {sender}")
            return {
                "heuristic_score": 100,
                "ml_score":        100,
                "ai_score":        100,
                "auth_penalty":    0,
                "trust_bonus":     0,
                "final_score":     100,
                "risk_level":      "CRITICAL",
                "result":          "PHISHING",
                "emoji":           "[CRITICAL]",
                "details":         {},
                "ml_details":      {},
                "ai_details":      {
                    "available":       True,
                    "verdict":         "PHISHING",
                    "confidence":      100,
                    "reasons":         ["Remetente bloqueado pelo administrador"],
                    "risk_indicators": ["Remetente na lista negra do sistema"]
                }
            }

        # ─── Heuristic analysis (40% weight) ───
        full_text = f"{subject} {body}"
        heuristic = run_heuristic_analysis(sender, subject, body)
        heuristic_score = heuristic["total_heuristic_score"]

        # ─── ML score (30% weight) ───
        ml_score = 0
        ml_result = {}
        if ML_AVAILABLE:
            try:
                ml_result = ml_predict(full_text)
                ml_score  = ml_result.get("ml_score", 0)
            except Exception as e:
                print(f"ML error: {e}")
                ml_result = {}

        # ─── AI score (30% weight) ───
        ai_score = 0
        ai_result = {}
        if AI_AVAILABLE:
            try:
                ai_result = analyze_with_ai(sender, subject, body)
                if ai_result and ai_result.get("available"):
                    ai_score = ai_result.get("ai_score", 0)
            except Exception as e:
                print(f"AI error: {e}")
                ai_result = {}

        # ─── Combined score ───
        if ML_AVAILABLE and AI_AVAILABLE and ai_result.get("available"):
            base_score = round(
                (heuristic_score * 0.4) +
                (ml_score        * 0.3) +
                (ai_score        * 0.3)
            )
        elif ML_AVAILABLE:
            base_score = round((heuristic_score * 0.6) + (ml_score * 0.4))
        else:
            base_score = heuristic_score

        # ─── AI override ───
        if AI_AVAILABLE and ai_result and ai_result.get("available"):
            ai_verdict    = ai_result.get("verdict", "")
            ai_confidence = ai_result.get("confidence", 0)
            domain_match  = ai_result.get("domain_match", True)

            # If AI says PHISHING with high confidence → boost score
            if ai_verdict == "PHISHING" and ai_confidence >= 80:
                base_score = max(base_score, round(ai_confidence * 0.8))

            # If domain mismatch → additional penalty
            if domain_match == False:
                base_score = min(base_score + 20, 100)

            # If AI says LEGITIMATE with high confidence → reduce score
            if ai_verdict == "LEGITIMATE" and ai_confidence >= 80:
                base_score = min(base_score, round((100 - ai_confidence) * 0.3))

        # ─── Auth penalty ───
        auth_penalty = 0
        if spf   == "FAIL": auth_penalty += 15
        if dkim  == "FAIL": auth_penalty += 10
        if dmarc == "FAIL": auth_penalty += 10

        # ─── Trusted sender bonus ───
        trust_bonus = 0
        if is_trusted_sender(sender) and spf == "PASS" and dkim == "PASS":
            trust_bonus = 20

        final_score = max(min(base_score + auth_penalty - trust_bonus, 100), 0)
        risk = get_risk_level(final_score)

        return {
            "heuristic_score": heuristic_score or 0,
            "ml_score":        ml_score or 0,
            "ai_score":        ai_score or 0,
            "auth_penalty":    auth_penalty or 0,
            "trust_bonus":     trust_bonus or 0,
            "final_score":     final_score or 0,
            "risk_level":      risk["level"],
            "result":          risk["result"],
            "emoji":           risk["emoji"],
            "details":         heuristic or {},
            "ml_details":      ml_result or {},
            "ai_details":      ai_result or {}
        }

    except Exception as e:
        print(f"calculate_score error: {e}")
        return {
            "heuristic_score": 0,
            "ml_score":        0,
            "ai_score":        0,
            "auth_penalty":    0,
            "trust_bonus":     0,
            "final_score":     0,
            "risk_level":      "LOW",
            "result":          "LEGITIMATE",
            "emoji":           "[LOW]",
            "details":         {},
            "ml_details":      {},
            "ai_details":      {}
        }


# ─── Quick test ───
if __name__ == "__main__":
    print(f"ML Available: {ML_AVAILABLE}")
    print(f"AI Available: {AI_AVAILABLE}")

    result = calculate_score(
        sender="security@paypal-support.tk",
        subject="URGENT: Your account has been suspended",
        body="Click here to verify your account immediately. Enter your password and bank details. http://paypal-login.tk",
        spf="FAIL",
        dkim="FAIL",
        dmarc="FAIL"
    )

    print("\n=== PHISHING SCORE RESULT ===")
    print(f"Heuristic Score: {result['heuristic_score']}")
    print(f"ML Score:        {result['ml_score']}")
    print(f"AI Score:        {result['ai_score']}")
    print(f"Auth Penalty:    {result['auth_penalty']}")
    print(f"Final Score:     {result['final_score']}")
    print(f"Risk Level:      {result['emoji']} {result['risk_level']}")
    print(f"Result:          {result['result']}")

    if result.get("ai_details", {}).get("available"):
        print(f"\nAI Verdict:    {result['ai_details']['verdict']}")
        print(f"AI Confidence: {result['ai_details']['confidence']}%")
        print(f"AI Reasons:    {result['ai_details']['reasons']}")