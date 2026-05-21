import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.heuristic import run_heuristic_analysis

RISK_LEVELS = [
    (86, 100, {"level": "CRITICAL", "result": "PHISHING",        "emoji": "[CRITICAL]"}),
    (61, 85,  {"level": "HIGH",     "result": "LIKELY PHISHING", "emoji": "[HIGH]"}),
    (31, 60,  {"level": "MEDIUM",   "result": "SUSPICIOUS",      "emoji": "[MEDIUM]"}),
    (0,  30,  {"level": "LOW",      "result": "LEGITIMATE",      "emoji": "[LOW]"}),
]

def get_risk_level(score):
	
	for (min_score, max_score , risk) in RISK_LEVELS:
		if min_score <= score <= max_score:
			return risk
	return {"level": "UNKNOWN", "result": "UNKNOWN", "emogi": "[UNKNOWN]"}


def calculate_score(sender,subject,body,spf,dkim,dmarc):


	heuristic = run_heuristic_analysis(sender, subject, body)
	base_score = heuristic["total_heuristic_score"]


	auth_penalty = 0
	
	if spf == "FAIL":
		auth_penalty += 15
	if dkim == "FAIL":
		auth_penalty += 10
	if dmarc == "FAIL":
		auth_penalty += 10
	

	final_score = min(base_score + auth_penalty, 100)

	risk = get_risk_level(final_score)


	return {
		"heuristic_score": base_score,
		"auth_penalty": auth_penalty,
		"final_score": final_score,
		"risk_level": risk["level"],
		"result": risk["result"],
		"emoji": risk["emoji"],
		"datails": heuristic
	}

if __name__ == "__main__":
    result = calculate_score(
        sender="security@paypal-support.com",
        subject="URGENT: Your account has been suspended",
        body="Click here to verify your account immediately. Enter your password. http://paypal-login.tk",
        spf="FAIL",
        dkim="FAIL",
        dmarc="FAIL"
    )

    print("=== PHISHING SCORE RESULT ===")
    print(f"Heuristic Score: {result['heuristic_score']}")
    print(f"Auth Penalty:    {result['auth_penalty']}")
    print(f"Final Score:     {result['final_score']}")
    print(f"Risk Level:      {result['emoji']} {result['risk_level']}")
    print(f"Result:          {result['result']}")

