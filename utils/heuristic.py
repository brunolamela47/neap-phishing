# ─── Trusted Domains Whitelist ───
TRUSTED_DOMAINS = [
    "google.com", "gmail.com", "googlemail.com",
    "microsoft.com", "outlook.com", "hotmail.com",
    "apple.com", "icloud.com",
    "amazon.com", "paypal.com",
    "facebook.com", "instagram.com",
    "linkedin.com", "twitter.com",
    "gov.pt", "at.gov.pt", "sns.gov.pt",
]


SUSPICIOUS_KEYWORDS = [
    # Urgency language
    "urgent", "immediately", "action required", "act now",
    "your account has been", "account suspended", "account blocked",
    "verify your account", "confirm your account", "update your account",

    # Credential requests
    "enter your password", "enter your credentials", "login here",
    "verify your identity", "confirm your identity", "authenticate",

    # Financial fraud
    "bank account", "credit card", "wire transfer", "payment required",
    "invoice attached", "refund", "transaction failed",

    # Portuguese phishing keywords
    "urgente", "clique aqui", "conta bloqueada", "conta suspensa",
    "verifique a sua conta", "confirme os seus dados", "aceda aqui",
    "palavra-passe", "atualize os seus dados", "pagamento em falta",
    "fatura em anexo", "transferencia bancaria", "dados bancarios",
    "premio", "ganhou", "parabens", "oferta especial"
]

# Suspicious URL patterns
SUSPICIOUS_URL_PATTERNS = [
    "bit.ly", "tinyurl", "goo.gl", "t.co",       # URL shorteners
    "login-", "secure-", "verify-", "update-",     # fake secure pages
    "paypal-", "amazon-", "google-", "microsoft-", # brand impersonation
    ".tk", ".ml", ".ga", ".cf", ".gq",             # free suspicious domains
    "http://",                                      # non-HTTPS
    "@",                                            # URL with @ is suspicious
]

# Suspicious sender patterns
SUSPICIOUS_SENDER_PATTERNS = [
    "noreply@", "no-reply@", "support@",
    "security@", "admin@", "helpdesk@",
    "paypal", "amazon", "microsoft", "google",
    "banco", "bank", "caixa", "mbway",
]

def analyze_keywords(text):
	text_lower = text.lower()
	found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text_lower]
	
	return {
		"found_keywords": found,
		"count": len(found),
		"score": min(len(found) * 10, 50)
	}

def analyze_urls(text):
	text_lower = text.lower()
	found = [pattern for pattern in SUSPICIOUS_URL_PATTERNS if pattern in text_lower]
	
	return {
		"found_patterns": found,
		"count": len(found),
		"score": min(len(found) * 15,30)
	}

def analyze_sender(sender):
	sender_lower = sender.lower()
	found = [pattern for pattern in SUSPICIOUS_SENDER_PATTERNS if pattern in sender_lower]
	
	return {
		"found_patterns": found,
		"count": len(found),
		"score": min(len(found) * 10,20)
	}

def run_heuristic_analysis(sender,subject,body):
	full_text = f"{subject} {body}"
	
	keyword_analysis = analyze_keywords(full_text)
	url_analysis = analyze_urls(full_text)
	sender_analysis = analyze_sender(sender)

	total_score = (
		keyword_analysis["score"] +
		url_analysis["score"] +
		sender_analysis["score"]
	)

	return {
		"sender_analysis": sender_analysis,
		"keyword_analysis": keyword_analysis,
		"url_analysis": url_analysis,
		"total_heuristic_score": min(total_score, 100)
	}
 
def is_trusted_sender(sender: str) -> bool:
    sender_lower = sender.lower()
    for domain in TRUSTED_DOMAINS:
        if f"@{domain}" in sender_lower or f".{domain}" in sender_lower:
            return True
    return False

if __name__ == "__main__":
	result = run_heuristic_analysis(
		sender="security@paypal-support.com",
		subject="URGENT: Your account has been suspend",
		body="Click here to verify your account immediately. Enter your pasword to confirm your identity. http://paypal-login.tk"
	)
	
	print("=== HEURISTIC ANALYSIS RESULT ===")
	print(f"Sender Score: 	{result['sender_analysis']['score']}")
	print(f"Keyword Score: 	{result['keyword_analysis']['score']}")
	print(f"URL Score:	{result['url_analysis']['score']}")
	print(f"Total Score:	{result['total_heuristic_score']}")
	print(f"Keywords Found:	{result['keyword_analysis']['found_keywords']}")

