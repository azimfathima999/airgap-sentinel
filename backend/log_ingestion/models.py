from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.sql import func
from backend.log_ingestion.database import Base
from datetime import datetime

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(255), index=True)
    level = Column(String(50), index=True)
    message = Column(Text)
    timestamp = Column(DateTime, index=True, default=datetime.utcnow)
    hostname = Column(String(255), nullable=True)
    service = Column(String(255), nullable=True, index=True)
    trace_id = Column(String(255), nullable=True, index=True)
    metadata = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    class Config:
        from_attributes = True
