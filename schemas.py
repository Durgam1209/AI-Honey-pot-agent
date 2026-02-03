from pydantic import BaseModel, Field
from typing import List, Optional

class MessageRequest(BaseModel):
    # This allows 'session_id', 'conversation_id', or 'cid'
    conversation_id: str = Field(..., alias="session_id")

    # This allows 'message', 'text', or 'content'
    message: str = Field(..., alias="text")

    class Config:
        # Allow both alias and field name
        populate_by_name = True

class EngagementMetrics(BaseModel):
    conversation_turns: int
    engagement_duration_seconds: float

class ExtractedIntelligence(BaseModel):
    bank_accounts: List[str] = Field(default_factory=list)
    upi_ids: List[str] = Field(default_factory=list)
    phishing_urls: List[str] = Field(default_factory=list)
    ifsc_codes: List[str] = Field(default_factory=list)
    wallet_addresses: List[str] = Field(default_factory=list)
    additional_notes: Optional[str] = ""

class HoneypotResponse(BaseModel):
    scam_detected: bool
    confidence_score: float
    agent_mode: str
    engagement_metrics: EngagementMetrics
    extracted_intelligence: ExtractedIntelligence
    agent_reply: str
