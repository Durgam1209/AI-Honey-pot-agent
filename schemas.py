from pydantic import BaseModel, Field
try:
    from pydantic import ConfigDict
except Exception:
    ConfigDict = None
try:
    from pydantic.version import VERSION as PYDANTIC_VERSION
except Exception:
    PYDANTIC_VERSION = "1"
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
    if ConfigDict and PYDANTIC_VERSION.startswith("2"):
        model_config = ConfigDict(populate_by_name=True, extra="ignore")
    else:
        class Config:
            allow_population_by_field_name = True
            extra = "ignore"

    session_id: str = Field(alias="sessionId")
    message: MessageContent
    conversationHistory: Optional[List[MessageContent]] = Field(default_factory=list)
    metadata: Optional[MessageMetadata] = None

# The EXACT response format the tester expects
class HoneypotResponse(BaseModel):
    status: str = "success"
    reply: str
