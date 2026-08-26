from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class LogBase(BaseModel):
    source: str
    level: str
    message: str
    hostname: Optional[str] = None
    service: Optional[str] = None
    trace_id: Optional[str] = None
    metadata: Optional[str] = None

class LogCreate(LogBase):
    pass

class LogUpdate(BaseModel):
    level: Optional[str] = None
    message: Optional[str] = None
    metadata: Optional[str] = None

class Log(LogBase):
    id: int
    timestamp: datetime
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class LogResponse(BaseModel):
    id: int
    source: str
    level: str
    message: str
    timestamp: datetime
    hostname: Optional[str]
    service: Optional[str]
    trace_id: Optional[str]

    class Config:
        from_attributes = True
