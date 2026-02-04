from fastapi import FastAPI, Header, HTTPException
import logging

from schemas import MessageRequest, HoneypotResponse
from config import API_KEY
from redis_store import append_message, get_history, set_history
from agent import generate_agent_response
from callback import send_final_callback

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)

app = FastAPI(title="Agentic Honeypot API")

@app.get("/")
@app.head("/")
def health_check():
    return {"status": "Agent is awake!", "endpoint": "/honeypot/message"}

@app.post("/honeypot/message", response_model=HoneypotResponse)
async def handle_message(data: MessageRequest, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401)

    # 1. Resolve history (client-provided overrides server state)
    if data.conversationHistory:
        set_history(data.sessionId, data.conversationHistory)
        history_items = list(data.conversationHistory)
    else:
        history_items = get_history(data.sessionId)

    append_message(data.sessionId, data.message)
    history_items.append(data.message)
    history = [m.text for m in history_items]
    
    # 2. Get AI analysis
    logging.info("History passed to LLM: %s", history)
    agent_data = generate_agent_response(history)
    
    # 3. Mandatory Callback Trigger
    # Rule: Send if scam is confirmed AND we have at least 5 messages
    if agent_data.get("scam_detected") and len(history) >= 5:
        send_final_callback(
            session_id=data.sessionId,
            history=history,
            intelligence=agent_data.get("extracted_intelligence", {}),
            notes=agent_data.get("reasoning", "Engaged scammer via Anjali persona.")
        )

    # 4. Return the EXACT keys required by Section 8
    return {
        "status": "success",
        "reply": agent_data.get("agent_reply")
    }
