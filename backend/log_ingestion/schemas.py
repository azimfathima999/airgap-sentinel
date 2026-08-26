from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class LogIngestRequest(BaseModel):
    logs: List[str]


class ParsedLog(BaseModel):
    timestamp: datetime
    source_ip: Optional[str] = None
    hostname: Optional[str] = None
    event_type: str
    username: Optional[str] = None
    message: str
    severity: Optional[str] = None
    raw_log: str


class LogResponse(BaseModel):
    id: int
    timestamp: datetime
    source_ip: Optional[str] = None
    hostname: Optional[str] = None
    event_type: str
    username: Optional[str] = None
    message: str
    severity: Optional[str] = None
    raw_log: str

    class Config:
        from_attributes = True


class IngestError(BaseModel):
    line: str
    error: str


class IngestResponse(BaseModel):
    log_ids: List[int]
    alert_ids: List[int]
    errors: List[IngestError] = []

class ThreatIntelImportItem(BaseModel):
    threat_type: str
    threat_name: str
    description: Optional[str] = None
    ioc_type: Optional[str] = None
    ioc_value: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[float] = None
    source: Optional[str] = None


class ThreatIntelImportRequest(BaseModel):
    updates: List[ThreatIntelImportItem]
