# backend/ollama_ai.py

# ─────────────────────────────────────────
# NEAP — Network Email Anti-Phishing
# Ollama AI Analysis with Sender Verification
# ─────────────────────────────────────────

import requests
import json

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL = "mistral"

def analyze_with_ai(sender: str, subject: str, body: str) -> dict:

    prompt = f"""És um especialista em cibersegurança português especializado na deteção de emails de phishing.

IMPORTANTE: Responde SEMPRE em português de Portugal.

Analisa este email e faz o seguinte:

1. Identifica que empresa/entidade está a ser impersonada (ex: Caixa Geral de Depósitos, PayPal, etc.)
2. Com base no teu conhecimento, qual é o domínio oficial de email dessa empresa?
3. Compara o remetente real com o domínio oficial — são iguais?
4. Se o domínio do remetente NÃO corresponde ao oficial, aumenta significativamente a suspeita de phishing.

Detalhes do email:
- Remetente: {sender}
- Assunto: {subject}
- Corpo: {body[:500]}

Responde APENAS neste formato JSON exato em português, sem mais nada:
{{
    "verdict": "PHISHING" ou "LEGITIMATE",
    "confidence": número entre 0 e 100,
    "impersonated_company": "nome da empresa impersonada ou null",
    "official_domain": "domínio oficial da empresa ou null",
    "sender_domain": "domínio do remetente",
    "domain_match": true ou false,
    "reasons": ["razão em português 1", "razão em português 2"],
    "risk_indicators": ["indicador em português 1"]
}}

LEMBRA-TE: Se o domínio do remetente não corresponder ao domínio oficial da empresa, isso é um forte indicador de phishing."""

    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": 500
        }
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=120)

        result = response.json()
        text = result.get("response", "").strip()

        start = text.find("{")
        end   = text.rfind("}") + 1

        if start == -1 or end == 0:
            return {"error": "Invalid response format", "available": False}

        parsed = json.loads(text[start:end])

        # ─── Domain mismatch penalty ───
        domain_match  = parsed.get("domain_match", True)
        base_conf     = parsed.get("confidence", 0)

        # If domain doesn't match → increase confidence significantly
        if not domain_match:
            final_confidence = min(base_conf + 30, 100)
        else:
            final_confidence = base_conf

        verdict = parsed.get("verdict", "UNKNOWN")

        return {
            "available":           True,
            "verdict":             verdict,
            "confidence":          final_confidence,
            "impersonated_company": parsed.get("impersonated_company"),
            "official_domain":     parsed.get("official_domain"),
            "sender_domain":       parsed.get("sender_domain"),
            "domain_match":        domain_match,
            "reasons":             parsed.get("reasons", []),
            "risk_indicators":     parsed.get("risk_indicators", []),
            "ai_score":            final_confidence if verdict == "PHISHING" else 100 - final_confidence
        }

    except requests.exceptions.ConnectionError:
        return {"available": False, "error": "Ollama not running"}
    except json.JSONDecodeError as e:
        return {"available": False, "error": "Could not parse AI response"}
    except Exception as e:
        return {"available": False, "error": str(e)}


# ─── Quick test ───
if __name__ == "__main__":
    result = analyze_with_ai(
        sender="seguranca@caixageral-bancos.tk",
        subject="URGENTE: A sua conta foi bloqueada",
        body="Clique aqui para verificar a sua conta. Introduza a sua palavra-passe e dados bancários."
    )

    print("=== AI ANALYSIS ===")
    print(f"Verdict:             {result.get('verdict')}")
    print(f"Confidence:          {result.get('confidence')}%")
    print(f"Impersonated:        {result.get('impersonated_company')}")
    print(f"Official Domain:     {result.get('official_domain')}")
    print(f"Sender Domain:       {result.get('sender_domain')}")
    print(f"Domain Match:        {result.get('domain_match')}")
    print(f"Reasons:             {result.get('reasons')}")