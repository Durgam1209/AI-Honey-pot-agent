import requests
import logging

def send_final_callback(session_id, history, intelligence, notes):
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": len(history),
        "extractedIntelligence": {
            "bankAccounts": intelligence.get("bank_accounts", []),
            "upiIds": intelligence.get("upi_ids", []),
            "phishingLinks": intelligence.get("phishing_urls", []),
            "phoneNumbers": intelligence.get("phone_numbers", []),
            "suspiciousKeywords": ["urgent", "verify", "blocked"]
        },
        "agentNotes": notes
    }
    
    try:
        url = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
        res = requests.post(url, json=payload, timeout=10)
        logging.info(f"Callback Status: {res.status_code}")
    except Exception as e:
        logging.error(f"Callback Failed: {e}")
