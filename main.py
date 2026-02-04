from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import StreamingResponse, JSONResponse
import json
import logging

from schemas import MessageRequest, HoneypotResponse
from config import API_KEY
from memory import add_message, get_history
from agent import generate_agent_response, generate_agent_reply_stream, generate_reply
from callback import send_final_callback

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)

app = FastAPI(title="Agentic Honeypot API")

@app.get("/")
@app.head("/")
def health_check():
    return {"status": "Agent is awake!", "endpoint": "/honeypot/stream"}

@app.post("/honeypot/message", response_model=HoneypotResponse)
async def handle_message(data: MessageRequest, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401)

    # 1. Extract the scam message
    scam_text = data.message.text
    history = [m["text"] for m in data.conversationHistory] + [scam_text]
    
    # 2. Get AI analysis
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

@app.post("/honeypot/stream")
def handle_message_stream(
    data: MessageRequest,
    request: Request,
    x_api_key: str = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401)

    if data.conversationHistory:
        for item in data.conversationHistory:
            add_message(data.sessionId, item.get("text", ""))

    add_message(data.sessionId, data.message.text)
    history = get_history(data.sessionId)

    accept_header = (request.headers.get("accept") or "").lower()
    if "text/event-stream" not in accept_header:
        agent_data = generate_agent_response(history)
        return JSONResponse(content={
            "status": "success",
            "reply": agent_data.get("agent_reply")
        })

    def event_generator():
        base_response = {
            "status": "success",
            "reply": ""
        }
        reply = ""
        sent_any = False
        for chunk in generate_agent_reply_stream(history):
            reply += chunk
            base_response["reply"] = reply
            sent_any = True
            yield f"data: {json.dumps(base_response)}\n\n"
        if not sent_any:
            reply = generate_reply(history, 0.0)
            base_response["reply"] = reply
            yield f"data: {json.dumps(base_response)}\n\n"
        yield f"data: {json.dumps(base_response)}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")
