from fastapi import FastAPI, Header, HTTPException
import logging

from schemas import MessageRequest, HoneypotResponse
from config import API_KEY
from redis_store import append_message, get_history, set_history, mark_callback_sent, redis_available
from agent import generate_agent_response
from callback import send_final_callback

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)

app = FastAPI(title="Agentic Honeypot API")

@app.on_event("startup")
def warn_if_redis_unavailable():
    if not redis_available():
        logging.warning("Redis unavailable at startup; falling back to in-memory store.")

@app.get("/")
@app.head("/")
def health_check():
    return {"status": "Agent is awake!", "endpoint": "/honeypot/message"}

@app.post("/honeypot/message", response_model=HoneypotResponse)
async def handle_message(data: MessageRequest, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # 1. Resolve history (client-provided overrides server state)
    if data.conversationHistory:
        set_history(data.session_id, data.conversationHistory)
        history_items = list(data.conversationHistory)
    else:
        history_items = get_history(data.session_id)

    append_message(data.session_id, data.message)
    history_items.append(data.message)
    history = [m.text for m in history_items]
    
    # 2. Get AI analysis
    logging.info("History passed to LLM: %s", history)
    agent_data = generate_agent_response(history)
    
    # 3. Mandatory Callback Trigger
    # Rule: Send if scam is confirmed AND we have at least 5 messages
    extracted = agent_data.get("extracted_intelligence", {})
    has_intel = any(extracted.get(key) for key in [
        "bank_accounts",
        "upi_ids",
        "phishing_urls",
        "phone_numbers",
        "ifsc_codes",
        "wallet_addresses",
    ])

    should_callback = agent_data.get("scam_detected") and (len(history) >= 5 or has_intel)
    if should_callback and mark_callback_sent(data.session_id):
        send_final_callback(
            session_id=data.session_id,
            history=history,
            intelligence=extracted,
            notes=agent_data.get("reasoning", "Engaged scammer via user persona.")
        )

    # 4. Return the EXACT keys required by Section 8
    return {
        "status": "success",
        "reply": agent_data.get("agent_reply")
    }
