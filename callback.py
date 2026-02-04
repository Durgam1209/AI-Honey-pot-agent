import logging

import requests

SUSPICIOUS_KEYWORDS = [
    "urgent",
    "verify",
    "verification",
    "account blocked",
    "account suspended",
    "kyc",
    "click",
    "link",
    "payment",
    "upi",
    "bank",
    "refund",
]

def _extract_suspicious_keywords(history_text: str):
    lowered = history_text.lower()
    found = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lowered:
            found.append(kw)
    return found

def send_final_callback(session_id, history, intelligence, notes):
    history_text = "\n".join(history)
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": len(history),
        "extractedIntelligence": {
            "bankAccounts": intelligence.get("bank_accounts", []),
            "upiIds": intelligence.get("upi_ids", []),
            "phishingLinks": intelligence.get("phishing_urls", []),
            "phoneNumbers": intelligence.get("phone_numbers", []),
            "suspiciousKeywords": _extract_suspicious_keywords(history_text),
        },
        "agentNotes": notes
    }
    
    try:
        url = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
        res = requests.post(url, json=payload, timeout=10)
        logging.info(f"Callback Status: {res.status_code}")
    except Exception as e:
        logging.error(f"Callback Failed: {e}")
