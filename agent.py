from google import genai
import json
import logging
import time
from typing import Dict, Iterable, List

from config import GEMINI_API_KEY, GEMINI_MODEL, MAX_CONTEXT_CHARS
from extract_intel import extract_intel
from bait_reply import bait_reply

MODEL_NAME = GEMINI_MODEL
SYSTEM_INSTRUCTION = (
    "MISSION: Detect scam intent and covertly extract actionable intelligence.\n"
    "PERSONA: You are a normal Indian user. Be polite, confused, and cooperative.\n"
    "STYLE: Ask short, specific clarifying questions; appear unsure; avoid direct compliance.\n"
    "STRATEGY: Use delayed compliance and intentional misunderstandings to keep them talking.\n"
    "GOAL: Extract Bank accounts, UPI IDs, IFSC codes, and Phishing URLs.\n"
    "RULES: Never reveal detection. Never mention AI. Vary sentence length."
)

_client = genai.Client(api_key=GEMINI_API_KEY)
logger = logging.getLogger(__name__)

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

def _extract_json(text: str) -> Dict | None:
    cleaned = text.strip().replace("```json", "").replace("```", "")
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(cleaned[start:end + 1])
    except json.JSONDecodeError:
        return None

def _dedupe(items: List[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result

def _extract_intelligence(text: str) -> Dict[str, List[str]]:
    return extract_intel(text)

def extract_intelligence_from_history(history: List[str]) -> Dict[str, List[str]]:
    return extract_intel("\n".join(history))

def estimate_confidence(history: List[str]) -> float:
    last_message = history[-1] if history else ""
    return detect_scam(last_message)

def generate_reply(history: List[str], scam_confidence: float = 0.0) -> str:
    if scam_confidence >= 0.6:
        return bait_reply(history)
    return "Okay, I’ll check and get back to you."

def _build_prompt(history: List[str]) -> str:
    system_prompt = (
        "You are a scam-baiting honeypot AI.\n\n"
        "Rules:\n"
        "- Act like a normal, slightly confused human\n"
        "- Never warn about scams\n"
        "- Never say you are an AI\n"
        "- Do NOT give real personal data\n"
        "- Ask innocent questions to extract:\n"
        "  - UPI IDs\n"
        "  - bank account numbers\n"
        "  - payment links\n"
        "- Keep replies short and casual\n"
    )

    full_prompt = system_prompt + "\nConversation:\n" + "\n".join(history)
    if len(history) > 3:
        full_prompt += "\n\nAsk for payment details politely."
    return full_prompt

def generate_agent_response(history: List[str]) -> Dict:
    """
    Acts as an autonomous AI Agent to covertly extract intelligence.
    Returns the strict JSON format required by your objectives.
    """
    context = "\n".join(history)
    if MAX_CONTEXT_CHARS and len(context) > MAX_CONTEXT_CHARS:
        context = context[-MAX_CONTEXT_CHARS:]

    prompt = (
        f"{SYSTEM_INSTRUCTION}\n\nConversation History:\n{context}\n\n"
        "Return ONLY a valid JSON object with keys:\n"
        "- scam_detected (bool)\n"
        "- confidence_score (float)\n"
        "- agent_mode (string)\n"
        "- agent_reply (string)\n"
        "- extracted_intelligence (object with bank_accounts, upi_ids, phishing_urls, ifsc_codes, wallet_addresses)\n"
        "- risk_analysis (object)\n"
    )
    if len(history) > 3:
        prompt += "\nAsk for payment details politely."

    last_message = history[-1] if history else ""
    confidence = detect_scam(last_message)
    regex_intel = _extract_intelligence(context)

    try:
        response = _client.models.generate_content(model=MODEL_NAME, contents=prompt)
        raw_text = (response.text or "").strip()
        parsed = _extract_json(raw_text)
        if parsed:
            extracted = parsed.get("extracted_intelligence", {})
            merged = {
                "bank_accounts": _dedupe(extracted.get("bank_accounts", []) + regex_intel["bank_accounts"]),
                "upi_ids": _dedupe(extracted.get("upi_ids", []) + regex_intel["upi_ids"]),
                "phishing_urls": _dedupe(extracted.get("phishing_urls", []) + regex_intel["phishing_urls"]),
                "ifsc_codes": _dedupe(extracted.get("ifsc_codes", []) + regex_intel["ifsc_codes"]),
                "wallet_addresses": _dedupe(extracted.get("wallet_addresses", []) + regex_intel["wallet_addresses"]),
            }
            parsed["extracted_intelligence"] = merged
            return parsed

        return {
            "scam_detected": confidence >= 0.5,
            "confidence_score": confidence,
            "agent_mode": "engaged" if confidence >= 0.5 else "monitoring",
            "agent_reply": raw_text or generate_reply(history, confidence),
            "extracted_intelligence": regex_intel,
            "risk_analysis": {"exposure_risk": "low", "reasoning": "Model reply without JSON envelope"}
        }
    except Exception:
        logger.exception("Gemini generate_content failed")
        return {
            "scam_detected": confidence >= 0.5,
            "confidence_score": confidence,
            "agent_mode": "engaged" if confidence >= 0.5 else "monitoring",
            "agent_reply": generate_reply(history, confidence),
            "extracted_intelligence": regex_intel,
            "risk_analysis": {"exposure_risk": "low", "reasoning": "Gemini API error"}
        }

def generate_agent_reply_stream(history: List[str]) -> Iterable[str]:
    prompt = _build_prompt(history)

    try:
        stream = _client.models.generate_content_stream(
            model=MODEL_NAME,
            contents=prompt
        )
        for chunk in stream:
            text = getattr(chunk, "text", None) or ""
            if text:
                yield text
        return
    except Exception:
        logger.exception("Gemini streaming failed; falling back to non-stream.")

    for attempt in range(2):
        try:
            response = _client.models.generate_content(model=MODEL_NAME, contents=prompt)
            text = (response.text or "").strip()
            if not text:
                return
            chunk_size = 40
            for i in range(0, len(text), chunk_size):
                yield text[i:i + chunk_size]
            return
        except Exception as exc:
            logger.exception("Gemini non-stream fallback failed.")
            if attempt == 0:
                time.sleep(3)
                continue
            return
