from pydantic import BaseModel
from typing import List, Optional

class MessageRequest(BaseModel):
    conversation_id: str
    message: str

class EngagementMetrics(BaseModel):
    conversation_turns: int
    engagement_duration_seconds: float

class ExtractedIntelligence(BaseModel):
    bank_accounts: List[str] = []
    upi_ids: List[str] = []
    phishing_urls: List[str] = []
    wallet_addresses: List[str] = []
    additional_notes: Optional[str] = ""

class HoneypotResponse(BaseModel):
    scam_detected: bool
    confidence_score: float
    agent_mode: str
    engagement_metrics: EngagementMetrics
    extracted_intelligence: ExtractedIntelligence
    agent_reply: str
