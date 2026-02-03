from fastapi import FastAPI, Header, HTTPException
import logging
import time

from schemas import MessageRequest, HoneypotResponse, EngagementMetrics, ExtractedIntelligence
from config import API_KEY
from memory import add_message, get_history, get_start_time
from agent import generate_agent_response

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)

app = FastAPI(title="Agentic Honeypot API")

@app.post("/honeypot/message", response_model=HoneypotResponse)
def handle_message(data: MessageRequest, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    add_message(data.conversation_id, data.message)
    history = get_history(data.conversation_id)

    # 1. Let the Agent analyze the whole history and return the full JSON object
    agent_data = generate_agent_response(history)

    # 2. Update metrics
    metrics = EngagementMetrics(
        conversation_turns=len(history),
        engagement_duration_seconds=time.monotonic() - get_start_time(data.conversation_id)
    )

    # 3. Return the AI's full autonomous analysis directly
    return HoneypotResponse(
        scam_detected=agent_data.get("scam_detected", False),
        confidence_score=agent_data.get("confidence_score", 0.0),
        agent_mode=agent_data.get("agent_mode", "monitoring"),
        engagement_metrics=metrics,
        extracted_intelligence=agent_data.get("extracted_intelligence", {}),
        agent_reply=agent_data.get("agent_reply", "I'm not sure I understand.")
    
    )
