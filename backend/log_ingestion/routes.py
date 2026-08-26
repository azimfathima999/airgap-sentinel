from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.log_ingestion.database import get_db
from backend.log_ingestion.models import Log
from backend.log_ingestion.schemas import LogCreate, LogResponse
from typing import List

router = APIRouter(prefix="/api/logs", tags=["logs"])

@router.post("/ingest", response_model=LogResponse, status_code=status.HTTP_201_CREATED)
def ingest_log(log: LogCreate, db: Session = Depends(get_db)):
    """Ingest a single log entry"""
    db_log = Log(**log.dict())
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log

@router.post("/ingest-batch", response_model=List[LogResponse], status_code=status.HTTP_201_CREATED)
def ingest_logs_batch(logs: List[LogCreate], db: Session = Depends(get_db)):
    """Ingest multiple log entries in batch"""
    db_logs = []
    for log in logs:
        db_log = Log(**log.dict())
        db.add(db_log)
        db_logs.append(db_log)
    db.commit()
    for log in db_logs:
        db.refresh(log)
    return db_logs

@router.get("/", response_model=List[LogResponse])
def get_logs(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """Get all logs with pagination"""
    logs = db.query(Log).offset(skip).limit(limit).all()
    return logs

@router.get("/{log_id}", response_model=LogResponse)
def get_log(log_id: int, db: Session = Depends(get_db)):
    """Get a specific log by ID"""
    log = db.query(Log).filter(Log.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    return log

@router.get("/source/{source}", response_model=List[LogResponse])
def get_logs_by_source(source: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """Get logs filtered by source"""
    logs = db.query(Log).filter(Log.source == source).offset(skip).limit(limit).all()
    return logs

@router.get("/level/{level}", response_model=List[LogResponse])
def get_logs_by_level(level: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """Get logs filtered by level"""
    logs = db.query(Log).filter(Log.level == level).offset(skip).limit(limit).all()
    return logs
