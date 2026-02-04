from pydantic import BaseModel, Field
from pydantic import ConfigDict
from typing import List, Optional

# Matches the "message" object in the tester's JSON
class MessageContent(BaseModel):
    sender: str
    text: str
    timestamp: int  # Epoch time in ms

class MessageMetadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None

# The main request body
class MessageRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    session_id: str = Field(alias="sessionId")
    message: MessageContent
    conversationHistory: List[MessageContent] = Field(default_factory=list)
    metadata: Optional[MessageMetadata] = None

# The EXACT response format the tester expects
class HoneypotResponse(BaseModel):
    status: str = "success"
    reply: str
