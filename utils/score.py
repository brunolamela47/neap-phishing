# utils/score.py

# ─────────────────────────────────────────
# NEAP — Network Email Anti-Phishing
# Phishing Score Engine
# ─────────────────────────────────────────

import sys
import os
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
        import sys, os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from database.database import get_connection
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id_blocked FROM BLOCKED_SENDERS WHERE sender = ?", (sender,))
        result = cursor.fetchone()
        conn.close()
        return result is not None
    except:
        return False
    
def calculate_score(sender: str, subject: str, body: str,
                    spf: str = "NONE", dkim: str = "NONE", dmarc: str = "NONE") -> dict:

    # ─── Heuristic analysis (40% weight) ───
    full_text = f"{subject} {body}"
    heuristic = run_heuristic_analysis(sender, subject, body)
    heuristic_score = heuristic["total_heuristic_score"]

    # ─── ML score (30% weight) ───
    ml_score = 0
    ml_result = {}
    if ML_AVAILABLE:
        ml_result = ml_predict(full_text)
        ml_score  = ml_result.get("ml_score", 0)

    # ─── AI score (30% weight) ───
    ai_score = 0
    ai_result = {}
    if AI_AVAILABLE:
        ai_result = analyze_with_ai(sender, subject, body)
        if ai_result.get("available"):
            ai_score = ai_result.get("ai_score", 0)

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
    if AI_AVAILABLE and ai_result.get("available"):
        ai_verdict    = ai_result.get("verdict", "")
        ai_confidence = ai_result.get("confidence", 0)
        domain_match  = ai_result.get("domain_match", True)

        if ai_verdict == "PHISHING" and ai_confidence >= 80:
            base_score = max(base_score, round(ai_confidence * 0.8))

        if domain_match == False:
            base_score = min(base_score + 20, 100)

    # ─── Auth penalty ───
    auth_penalty = 0
    if spf   == "FAIL": auth_penalty += 15
    if dkim  == "FAIL": auth_penalty += 10
    if dmarc == "FAIL": auth_penalty += 10

    # ─── Trusted sender bonus ───
    trust_bonus = 0
    if is_trusted_sender(sender) and spf != "FAIL":
        trust_bonus = 20

    final_score = max(min(base_score + auth_penalty - trust_bonus, 100), 0)
    risk = get_risk_level(final_score)

    if is_blocked_sender(sender):
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
            "ai_details":      {"available": True, "verdict": "PHISHING", "confidence": 100,
                                "reasons": ["Remetente bloqueado pelo administrador"],
                                "risk_indicators": ["Remetente na lista negra"]}
        }