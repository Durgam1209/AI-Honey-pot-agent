from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
import logging
import time
from typing import Any

from schemas import MessageContent, HoneypotResponse
from config import API_KEY
from redis_store import append_message, get_history, set_history, mark_callback_sent, redis_available
from agent import generate_agent_response, extract_intelligence_from_history
from callback import send_final_callback

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)

app = FastAPI(title="Agentic Honeypot API")
SAFE_FALLBACK_REPLY = "I'm not sure about this. Could you please share the official helpline or website so I can verify?"

@app.on_event("startup")
def warn_if_redis_unavailable():
    if not redis_available():
        logging.warning("Redis unavailable at startup; falling back to in-memory store.")

@app.get("/")
@app.head("/")
def health_check():
    return {"status": "Agent is awake!", "endpoint": "/honeypot/message"}

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logging.error("VAL_ERROR: %s", exc.errors())
    body = await request.body()
    logging.error("RECEIVED_BODY: %s", body.decode(errors="replace"))
    return JSONResponse(
        status_code=422,
        content={
            "status": "error",
            "message": "Invalid Request Body",
            "details": exc.errors(),
        },
    )

def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default

def _coerce_message(raw: Any, fallback_text: str) -> MessageContent:
    now_ms = int(time.time() * 1000)
    if isinstance(raw, dict):
        sender = raw.get("sender") or "user"
        text = raw.get("text") or raw.get("message") or fallback_text or ""
        timestamp = _safe_int(raw.get("timestamp"), now_ms)
    elif isinstance(raw, str):
        sender = "user"
        text = raw
        timestamp = now_ms
    else:
        sender = "user"
        text = fallback_text or ""
        timestamp = now_ms

    return MessageContent(sender=sender, text=text, timestamp=timestamp)

async def _read_json_or_empty(request: Request) -> dict:
    try:
        payload = await request.json()
        if isinstance(payload, dict):
            return payload
        return {}
    except Exception:
        return {}

async def _handle_message_universal(
    request: Request,
    x_api_key: str | None,
):
    if API_KEY and x_api_key != API_KEY:
        logging.warning("Auth failed. Expected %s, got %s", API_KEY, x_api_key)
        raise HTTPException(status_code=401, detail="Unauthorized")

    payload = await _read_json_or_empty(request)
    session_id = (
        payload.get("sessionId")
        or payload.get("session_id")
        or payload.get("session")
        or f"anonymous-{int(time.time() * 1000)}"
    )

    message_raw = payload.get("message") if isinstance(payload, dict) else None
    message = _coerce_message(message_raw, fallback_text=payload.get("text", ""))

    history_raw = payload.get("conversationHistory") or payload.get("conversation_history")
    history_items = []
    if isinstance(history_raw, list):
        for item in history_raw:
            history_items.append(_coerce_message(item, fallback_text=""))

    # 1. Resolve history (client-provided overrides server state)
    if history_items:
        set_history(session_id, history_items)
    else:
        history_items = get_history(session_id)

    append_message(session_id, message)
    history_items.append(message)
    history = [
        f"{m.sender}: {m.text}" if m.sender else m.text
        for m in history_items
    ]
    
    # 2. Get AI analysis
    logging.info("History passed to LLM: %s", history)
    try:
        agent_data = generate_agent_response(history)
    except Exception:
        logging.exception("Agent response failed; using safe fallback reply.")
        agent_data = {
            "scam_detected": False,
            "confidence_score": 0.0,
            "agent_mode": "monitoring",
            "agent_reply": SAFE_FALLBACK_REPLY,
            "extracted_intelligence": extract_intelligence_from_history(history),
            "risk_analysis": {"exposure_risk": "low", "reasoning": "Fallback due to agent error"},
        }
    
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
    if should_callback and mark_callback_sent(session_id):
        send_final_callback(
            session_id=session_id,
            history=history,
            intelligence=extracted,
            notes=agent_data.get("reasoning"),
            risk_analysis=agent_data.get("risk_analysis"),
        )

    # 4. Return the EXACT keys required by Section 8
    reply_text = agent_data.get("agent_reply") or SAFE_FALLBACK_REPLY
    reply_message = MessageContent(
        sender="honeypot",
        text=reply_text,
        timestamp=int(time.time() * 1000),
    )
    append_message(session_id, reply_message)

    # Simulated typing delay to reduce bot-like responses and smooth rate limits
    time.sleep(0.4)

    return {
        "status": "success",
        "reply": reply_text
    }

@app.post("/honeypot/message", response_model=HoneypotResponse)
async def handle_message(
    request: Request,
    x_api_key: str | None = Header(None, alias="x-api-key"),
):
    return await _handle_message_universal(request, x_api_key)

# Robust fallback: accept POSTs to "/" and route to honeypot logic
@app.post("/", response_model=HoneypotResponse)
async def handle_root_post(
    request: Request,
    x_api_key: str | None = Header(None, alias="x-api-key"),
):
    return await _handle_message_universal(request, x_api_key)
