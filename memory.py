from collections import defaultdict
from threading import Lock
import time

from config import MAX_HISTORY
from schemas import MessageContent

_lock = Lock()

conversations = defaultdict(lambda: {
    "history": [],
    "start_time": time.monotonic(),
    "extracted": {
        "bank_accounts": [],
        "upi_ids": [],
        "phishing_urls": [],
        "ifsc_codes": [],
        "wallet_addresses": []
    }
})

def add_message(conversation_id: str, message: MessageContent) -> dict:
    with _lock:
        convo = conversations[conversation_id]
        convo["history"].append(message)

        if MAX_HISTORY and len(convo["history"]) > MAX_HISTORY:
            convo["history"] = convo["history"][-MAX_HISTORY:]

        return convo

def get_history(conversation_id: str) -> list:
    with _lock:
        return list(conversations[conversation_id]["history"])

def get_start_time(conversation_id: str) -> float:
    with _lock:
        return conversations[conversation_id]["start_time"]
