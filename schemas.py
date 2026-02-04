from pydantic import BaseModel
from typing import List, Optional

# Matches the "message" object in the tester's JSON
class MessageContent(BaseModel):
    sender: str
    text: str
    timestamp: int  # Epoch time in ms

# The main request body
class MessageRequest(BaseModel):
    sessionId: str
    message: MessageContent
    conversationHistory: List[dict] = []
    metadata: Optional[dict] = {}

# The EXACT response format the tester expects
class HoneypotResponse(BaseModel):
    status: str = "success"
    reply: str
