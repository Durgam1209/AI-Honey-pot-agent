import google.generativeai as genai
import json
import time
from config import GEMINI_API_KEY

# Configure the SDK with the verified model path
if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY missing. Check your .env file!")

genai.configure(api_key=GEMINI_API_KEY)

def detect_scam(message: str) -> float:
    """Multi-signal analysis for scam detection."""
    signals = [ "upi", "account", "bank", "verify", "verification",
    "refund", "prize", "lottery", "offer", "limited",
    "click", "link", "payment", "urgent", "kyc"]
    # Intent detection: Check for urgency + payment keywords
    confidence = 0.0
    msg_lower = message.lower()
    
    if any(word in msg_lower for word in signals):
        confidence += 0.5
    if "urgent" in msg_lower or "now" in msg_lower:
        confidence += 0.3
    if "bank" in msg_lower or "upi" in msg_lower:
        confidence += 0.2
        
    return min(confidence, 1.0)

def generate_agent_response(history: list) -> dict:
    """
    Acts as an autonomous AI Agent to covertly extract intelligence.
    Returns the strict JSON format required by your objectives.
    """
    # Use the explicit path to avoid the 404 version mismatch
    model = genai.GenerativeModel("models/gemini-1.5-flash") 
    
    context = "\n".join(history)
    
    # The System Instruction defines the Agent's soul
    system_instruction = """
    MISSION: Detect scam intent and covertly extract actionable intelligence.
    PERSONA: You are a normal Indian user. Be polite, confused, and cooperative.
    STRATEGY: Use delayed compliance and intentional misunderstandings to keep them talking.
    GOAL: Extract Bank accounts, UPI IDs, IFSC codes, and Phishing URLs.
    RULES: Never reveal detection. Never mention AI. Vary sentence length.
    """

    prompt = f"{system_instruction}\n\nConversation History:\n{context}\n\nReturn ONLY a valid JSON object."

    try:
        response = model.generate_content(prompt)
        # Parse the AI's JSON output
        return json.loads(response.text.strip().replace('```json', '').replace('```', ''))
    except Exception:
        # Fallback to a basic JSON if AI parsing fails
        return {
            "scam_detected": True,
            "confidence_score": 0.9,
            "agent_mode": "engaged",
            "agent_reply": "Oh, I'm sorry! I'm trying to find my card. Which UPI ID should I send it to again?",
            "extracted_intelligence": {"upi_ids": [], "bank_accounts": []},
            "risk_analysis": {"exposure_risk": "low", "reasoning": "Standard cooperative response"}
        }