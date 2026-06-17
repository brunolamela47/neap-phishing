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

Aqui estão exemplos para te guiar:

EXEMPLO 1 - LEGITIMATE:
Remetente: joao@empresa.pt
Assunto: Reunião amanhã
Corpo: Olá, a reunião de amanhã foi adiada para as 15h. Cumprimentos.
→ verdict: LEGITIMATE, confidence: 95
→ Razão: Conteúdo normal, sem pedidos suspeitos

EXEMPLO 2 - LEGITIMATE:
Remetente: noreply@gmail.com
Assunto: Teste
Corpo: teste
→ verdict: LEGITIMATE, confidence: 90
→ Razão: Corpo simples sem indicadores de phishing

EXEMPLO 3 - PHISHING:
Remetente: seguranca@caixageral-bancos.tk
Assunto: URGENTE: Conta bloqueada
Corpo: A sua conta foi bloqueada. Clique aqui para verificar: http://caixa-login.tk. Introduza a sua palavra-passe.
→ verdict: PHISHING, confidence: 98
→ Razão: Pedido de credenciais, URL suspeito, domínio falso

EXEMPLO 4 - PHISHING:
Remetente: premio@ganhouagora.ga
Assunto: Parabéns! Ganhou 5000€
Corpo: Foi selecionado para receber 5000€. Clique aqui e introduza os seus dados bancários para receber o prémio.
→ verdict: PHISHING, confidence: 99
→ Razão: Oferta falsa de prémio, pedido de dados bancários

─────────────────────────

Agora analisa este email:
- Remetente: {sender}
- Assunto: {subject}
- Corpo: {body[:500]}

Regras:
- Se o corpo for simples (teste, olá, reunião, etc.) → LEGITIMATE
- Só PHISHING se houver: pedidos de password/dados bancários, URLs suspeitos, urgência excessiva, prémios falsos
- O domínio diferente NÃO é suficiente para ser phishing sozinho

Responde APENAS neste formato JSON em português, sem mais nada:
{{
    "verdict": "PHISHING" ou "LEGITIMATE",
    "confidence": número entre 0 e 100,
    "impersonated_company": "nome da empresa ou null",
    "official_domain": "domínio oficial ou null",
    "sender_domain": "domínio do remetente",
    "domain_match": true ou false,
    "reasons": ["razão em português 1", "razão em português 2"],
    "risk_indicators": ["indicador em português 1"]
}}"""

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