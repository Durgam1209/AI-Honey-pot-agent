from fastapi import FastAPI, Header, HTTPException
import time

from schemas import MessageRequest, HoneypotResponse, EngagementMetrics, ExtractedIntelligence
from config import API_KEY
from memory import conversations
from agent import detect_scam, generate_agent_response

app = FastAPI(title="Agentic Honeypot API")

@app.post("/honeypot/message", response_model=HoneypotResponse)
def handle_message(data: MessageRequest, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    convo = conversations[data.conversation_id]
    convo["history"].append(data.message)

    # 1. Let the Agent analyze the whole history and return the full JSON object
    agent_data = generate_agent_response(convo["history"])

    # 2. Update metrics
    metrics = EngagementMetrics(
        conversation_turns=len(convo["history"]),
        engagement_duration_seconds=time.time() - convo["start_time"]
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