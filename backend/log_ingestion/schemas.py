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
