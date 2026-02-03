from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import StreamingResponse, JSONResponse
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

@app.get("/")
def health_check():
    return {"status": "Agent is awake!", "endpoint": "/honeypot/stream"}

@app.post("/honeypot/message", response_model=HoneypotResponse)
async def handle_message(request: Request, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    raw_body = await request.json()
    print(f"DEBUG - Incoming Tester Data: {raw_body}")
    data = MessageRequest.model_validate(raw_body)

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
def handle_message_stream(
    data: MessageRequest,
    request: Request,
    x_api_key: str = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    add_message(data.conversation_id, data.message)
    history = get_history(data.conversation_id)

    accept_header = (request.headers.get("accept") or "").lower()
    if "text/event-stream" not in accept_header:
        agent_data = generate_agent_response(history)
        metrics = EngagementMetrics(
            conversation_turns=len(history),
            engagement_duration_seconds=time.monotonic() - get_start_time(data.conversation_id)
        )
        extracted_intelligence = agent_data.get("extracted_intelligence", {})

        return JSONResponse(
            content=HoneypotResponse(
                scam_detected=agent_data.get("scam_detected", False),
                confidence_score=agent_data.get("confidence_score", 0.0),
                agent_mode=agent_data.get("agent_mode", "monitoring"),
                engagement_metrics=metrics,
                extracted_intelligence=extracted_intelligence,
                agent_reply=agent_data.get("agent_reply", "")
            ).model_dump()
        )

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
        sent_any = False
        for chunk in generate_agent_reply_stream(history):
            reply += chunk
            base_response["agent_reply"] = reply
            sent_any = True
            yield f"data: {json.dumps(base_response)}\n\n"
        if not sent_any:
            reply = generate_reply(history, confidence)
            base_response["agent_reply"] = reply
            yield f"data: {json.dumps(base_response)}\n\n"
        yield f"data: {json.dumps(base_response)}\n\n"

        if confidence >= 0.5:
            final_extracted = extract_intelligence_from_history(history)
            log_scam(
                session_id=data.conversation_id,
                intel=final_extracted,
                confidence=confidence
            )
        

    return StreamingResponse(event_generator(), media_type="text/event-stream")
