import json
from typing import List

import redis

from config import REDIS_URL
from schemas import MessageContent

_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)


def _key(session_id: str) -> str:
    return f"honeypot:history:{session_id}"

def _callback_key(session_id: str) -> str:
    return f"honeypot:callback_sent:{session_id}"


def get_history(session_id: str) -> List[MessageContent]:
    items = _client.lrange(_key(session_id), 0, -1)
    result: List[MessageContent] = []
    for raw in items:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            continue
        try:
            result.append(MessageContent(**payload))
        except Exception:
            continue
    return result


def append_message(session_id: str, message: MessageContent) -> None:
    _client.rpush(_key(session_id), json.dumps(message.model_dump()))


def set_history(session_id: str, messages: List[MessageContent]) -> None:
    key = _key(session_id)
    pipeline = _client.pipeline()
    pipeline.delete(key)
    if messages:
        pipeline.rpush(key, *[json.dumps(m.model_dump()) for m in messages])
    pipeline.execute()

def mark_callback_sent(session_id: str) -> bool:
    """
    Returns True if we just marked it, False if it was already marked.
    """
    return _client.setnx(_callback_key(session_id), "1")

def callback_already_sent(session_id: str) -> bool:
    return _client.exists(_callback_key(session_id)) == 1
