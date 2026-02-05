# Honey-Pot AI

An agentic honeypot API that safely engages scammer-style messages, extracts scam intelligence, and reports a final callback with analysis. It includes robust request handling, persona consistency, and detailed logging.

**What it does**
- Accepts messages from any client (browser, Postman, evaluator).
- Responds as a cautious “victim” persona to keep scammers engaged.
- Extracts intel (UPI IDs, bank accounts, IFSC codes, phone numbers, URLs).
- Logs every message and a final summary to `data/scam_logs.csv`.
- Sends a mandatory callback with extracted intelligence and agent notes.

## Quick Start

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Create `.env` in the project root:
```env
HONEYPOT_API_KEY=your_honeypot_api_key
GROQ_API_KEY=your_groq_api_key
GROQ_MODEL=llama-3.1-8b-instant
REDIS_URL=redis://localhost:6379/0
MAX_HISTORY=50
MAX_CONTEXT_CHARS=8000
```

3. Run the server:
```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

## API

### Health Check
`GET /` or `HEAD /`

Response:
```json
{"status":"Agent is awake!","endpoint":"/honeypot/message"}
```

### Honeypot Message (Primary)
`POST /honeypot/message`

Headers:
- `x-api-key`: required (must match `HONEYPOT_API_KEY`)

Body (flexible; extra fields are ignored):
```json
{
  "sessionId": "session-001",
  "message": {
    "sender": "scammer",
    "text": "URGENT: Your account is blocked. Send OTP now.",
    "timestamp": 1738770000000
  },
  "conversationHistory": [
    {"sender":"scammer","text":"Hello","timestamp":1738769000000}
  ]
}
```

Response:
```json
{"status":"success","reply":"I’m not sure what’s going on. Can you share the official helpline?"}
```

### Fallback POST
`POST /`  
If a client accidentally POSTs to `/`, the request is routed to the honeypot logic to prevent 405 errors.

## Logging
All messages and final summaries are appended to:
`data/scam_logs.csv`

Columns:
```
timestamp, session_id, event_type, sender, message, scam_detected,
confidence_score, upi_ids, bank_accounts, ifsc_codes, phishing_urls,
phone_numbers, suspicious_phrases, sophistication
```

## Intelligence Extraction
The system extracts and normalizes:
- UPI IDs (e.g., `name@bank`)
- Bank account numbers (handles spaces/dashes)
- IFSC codes (handles `0` vs `O`)
- Phone numbers (normalized to `+91XXXXXXXXXX`)
- URLs

## Callback
When a scam is detected and enough evidence is gathered, the API sends:
`POST https://hackathon.guvi.in/api/updateHoneyPotFinalResult`

Payload includes:
- `extractedIntelligence`
- `agentNotes` with contextual evidence and sophistication assessment

## Notes
- If the Groq API fails, the server returns a safe fallback reply instead of an error.
- A short typing delay is added to responses to reduce bot-like behavior.
- Redis is optional; the system falls back to in-memory storage if unavailable.

## File Map
- `main.py` — FastAPI app + routing
- `agent.py` — agent logic & prompt orchestration
- `extract_intel.py` — regex-based intel extraction
- `callback.py` — final callback reporting
- `logger.py` — CSV logging
- `redis_store.py` / `memory.py` — storage layers

---
If you want, I can add a sample Postman collection or a test script.
