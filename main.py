from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import StreamingResponse
from extract_intel import extract_intel
from logger import log_scam

import json
import logging
import time

from schemas import MessageRequest, HoneypotResponse, EngagementMetrics, ExtractedIntelligence
from config import API_KEY
from memory import add_message, get_history, get_start_time
from agent import generate_agent_response, generate_agent_reply_stream, estimate_confidence, extract_intelligence_from_history, generate_reply, detect_scam

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

    confidence = detect_scam(data.message)
    is_scam = confidence >= 0.6
    if is_scam:
        reply = generate_reply(history, confidence)
        mode = "engaged"
    else:
        reply = generate_reply(history, confidence)
        mode = "monitoring"

    # 1. Let the Agent analyze the whole history and return the full JSON object
    agent_data = generate_agent_response(history)

    # 2. Update metrics
    metrics = EngagementMetrics(
        conversation_turns=len(history),
        engagement_duration_seconds=time.monotonic() - get_start_time(data.conversation_id)
    )

    extracted_intelligence = agent_data.get("extracted_intelligence", {})
    if is_scam:
        log_scam(
            session_id=data.conversation_id,
            intel=extracted_intelligence,
            confidence=confidence
        )

    # 3. Return the AI's full autonomous analysis directly
    return HoneypotResponse(
        scam_detected=agent_data.get("scam_detected", is_scam),
        confidence_score=agent_data.get("confidence_score", confidence),
        agent_mode=agent_data.get("agent_mode", mode),
        engagement_metrics=metrics,
        extracted_intelligence=extracted_intelligence,
        agent_reply=agent_data.get("agent_reply", reply)
    
    )

@app.post("/honeypot/stream")
def handle_message_stream(data: MessageRequest, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    add_message(data.conversation_id, data.message)
    history = get_history(data.conversation_id)

    def event_generator():
        confidence = estimate_confidence(history)
        extracted = extract_intelligence_from_history(history)
        base_response = {
            "scam_detected": confidence >= 0.5,
            "confidence_score": confidence,
            "agent_mode": "engaged" if confidence >= 0.5 else "monitoring",
            "engagement_metrics": {
                "conversation_turns": len(history),
                "engagement_duration_seconds": time.monotonic() - get_start_time(data.conversation_id),
            },
            "extracted_intelligence": extracted,
            "agent_reply": ""
        }
        reply = ""
        for chunk in generate_agent_reply_stream(history):
            reply += chunk
            base_response["agent_reply"] = reply
            yield f"data: {json.dumps(base_response)}\n\n"
        yield f"data: {json.dumps(base_response)}\n\n"
        

    return StreamingResponse(event_generator(), media_type="text/event-stream")
