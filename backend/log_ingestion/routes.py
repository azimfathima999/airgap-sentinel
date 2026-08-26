from datetime import datetime, timedelta, UTC
import re
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.log_ingestion.database import get_db
from backend.log_ingestion.models import Log, Alert, Report, ThreatIntel
from backend.log_ingestion.schemas import ThreatIntelImportRequest

router = APIRouter(tags=["logs"])


# ============================================================
# REQUEST SCHEMAS
# ============================================================

class IngestRequest(BaseModel):
    logs: List[str] = Field(default_factory=list)


class BatchIngestRequest(BaseModel):
    logs: List[str] = Field(default_factory=list)


class AlertStatusUpdate(BaseModel):
    status: str


# ============================================================
# LOG PARSER
# ============================================================

SYSLOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<service>[\w.-]+)"
    r"(?:\[\d+\])?:\s+"
    r"(?P<message>.+)$"
)

FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?"
    r"(?P<username>\S+)\s+from\s+"
    r"(?P<source_ip>\S+)"
)

SUCCESSFUL_LOGIN_PATTERN = re.compile(
    r"Accepted password for "
    r"(?P<username>\S+)\s+from\s+"
    r"(?P<source_ip>\S+)"
)


def parse_log_line(raw_log: str) -> dict:
    """
    Parse an SSH/syslog line into the fields used by the logs table.

    Example:
    Aug 26 22:00:01 server sshd[600]:
    Accepted password for alice from 10.0.0.50 port 2200
    """

    if not raw_log or not raw_log.strip():
        raise ValueError("Log line is empty")

    raw_log = raw_log.strip()

    match = SYSLOG_PATTERN.match(raw_log)

    if not match:
        raise ValueError("Unsupported log format")

    month = match.group("month")
    day = match.group("day")
    time = match.group("time")
    hostname = match.group("hostname")
    service = match.group("service")
    message = re.sub(r"\s+", " ", match.group("message")).strip()

    # Current PoC date is 2026.  Syslog does not contain a year.
    timestamp = datetime.strptime(
        f"2026 {month} {day} {time}",
        "%Y %b %d %H:%M:%S"
    )

    failed = FAILED_LOGIN_PATTERN.search(message)
    successful = SUCCESSFUL_LOGIN_PATTERN.search(message)

    username: Optional[str] = None
    source_ip: Optional[str] = None

    if failed:
        event_type = "FAILED_LOGIN"
        severity = "HIGH"
        username = failed.group("username")
        source_ip = failed.group("source_ip")

    elif successful:
        event_type = "SUCCESSFUL_LOGIN"
        severity = "INFO"
        username = successful.group("username")
        source_ip = successful.group("source_ip")

    else:
        event_type = "OTHER"
        severity = "INFO"

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "hostname": hostname,
        "event_type": event_type,
        "username": username,
        "message": message,
        "severity": severity,
        "raw_log": raw_log,
        "service": service,
    }


# ============================================================
# HELPER
# ============================================================

def log_to_dict(log) -> dict:
    """
    Convert a SQLAlchemy Log object to a JSON-safe dictionary.

    This intentionally does not depend on LogResponse from schemas.py.
    """

    return {
        "id": log.id,
        "timestamp": log.timestamp,
        "source_ip": getattr(log, "source_ip", None),
        "hostname": getattr(log, "hostname", None),
        "event_type": getattr(log, "event_type", None),
        "username": getattr(log, "username", None),
        "message": getattr(log, "message", None),
        "severity": getattr(log, "severity", None),
        "raw_log": getattr(log, "raw_log", None),
        "created_at": getattr(log, "created_at", None),
        "updated_at": getattr(log, "updated_at", None),
    }


# ============================================================
# ALERT DETECTION
# ============================================================

def detect_brute_force(db: Session, log: Log):
    """
    Create a brute-force alert when the same source IP has
    3 or more failed logins within a 5-minute window.
    """

    if log.event_type != "FAILED_LOGIN" or not log.source_ip:
        return None

    window_start = log.timestamp - timedelta(minutes=5)

    failed_count = (
        db.query(Log)
        .filter(
            Log.source_ip == log.source_ip,
            Log.event_type == "FAILED_LOGIN",
            Log.timestamp >= window_start,
            Log.timestamp <= log.timestamp,
        )
        .count()
    )

    if failed_count < 3:
        return None

    # Avoid creating duplicate open alerts for the same source IP
    existing_alert = (
        db.query(Alert)
        .filter(
            Alert.source_ip == log.source_ip,
            Alert.alert_type == "brute_force",
            Alert.status == "OPEN",
        )
        .first()
    )

    if existing_alert:
        return existing_alert

    alert = Alert(
        title="SSH Brute Force Detected",
        description=(
            f"{failed_count} failed SSH login attempts detected "
            f"from {log.source_ip} within 5 minutes."
        ),
        status="OPEN",
        severity="HIGH",
        source_log_id=log.id,
        hostname=log.hostname,
        source_ip=log.source_ip,
        alert_type="brute_force",
        rule_triggered="3 failed SSH logins from same IP within 5 minutes",
        triggered_at=log.timestamp,
    )

    db.add(alert)
    db.flush()

    return alert


# ============================================================
# INGEST LOGS
# ============================================================

@router.post("/logs/ingest")
def ingest_logs(
    request: IngestRequest,
    db: Session = Depends(get_db)
):
    """
    Ingest one or more raw log lines.

    Expected JSON:

    {
        "logs": [
            "Aug 26 22:00:01 server sshd[600]: Accepted password for alice from 10.0.0.50 port 2200"
        ]
    }
    """

    results = []
    stored_log_ids = []
    alert_ids = []
    errors = []

    for index, raw_log in enumerate(request.logs):
        try:
            parsed = parse_log_line(raw_log)

            db_log = Log(
                timestamp=parsed["timestamp"],
                source_ip=parsed["source_ip"],
                hostname=parsed["hostname"],
                event_type=parsed["event_type"],
                username=parsed["username"],
                message=parsed["message"],
                severity=parsed["severity"],
                raw_log=parsed["raw_log"],
            )

            db.add(db_log)
            db.flush()

            alert = detect_brute_force(db, db_log)
            if alert is not None:
                alert_ids.append(alert.id)

            stored_log_ids.append(db_log.id)

            results.append({
                "index": index,
                "status": "stored",
                "log": log_to_dict(db_log),
            })

        except Exception as exc:
            errors.append({
                "index": index,
                "status": "error",
                "message": str(exc),
                "raw_log": raw_log,
            })

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise

    return {
        "status": "success",
        "ingested": len(stored_log_ids),
        "failed": len(errors),
        "log_ids": stored_log_ids,
        "alert_ids": alert_ids,
        "results": results,
        "errors": errors,
    }


# ============================================================
# BATCH INGEST
# ============================================================

@router.post("/logs/ingest-batch")
def ingest_logs_batch(
    request: BatchIngestRequest,
    db: Session = Depends(get_db)
):
    """
    Batch version of /logs/ingest.

    Accepts:

    {
        "logs": [
            "raw log 1",
            "raw log 2"
        ]
    }
    """

    return ingest_logs(request, db)


# ============================================================
# GET ALL LOGS
# ============================================================

@router.get("/logs")
def get_logs(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """
    Return stored logs.
    """

    logs = (
        db.query(Log)
        .order_by(Log.timestamp.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

    return {
        "count": len(logs),
        "logs": [log_to_dict(log) for log in logs],
    }


# ============================================================
# GET SINGLE LOG
# ============================================================

@router.get("/logs/{log_id}")
def get_log(
    log_id: int,
    db: Session = Depends(get_db)
):
    """
    Return exactly one log.

    This fixes the previous /logs/8 problem where the route
    returned [] and FastAPI attempted to validate it as an object.
    """

    log = (
        db.query(Log)
        .filter(Log.id == log_id)
        .first()
    )

    if log is None:
        raise HTTPException(
            status_code=404,
            detail=f"Log {log_id} not found"
        )

    return log_to_dict(log)


# ============================================================
# GET LOGS BY SOURCE IP
# ============================================================

@router.get("/logs/source/{source_ip}")
def get_logs_by_source_ip(
    source_ip: str,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    logs = (
        db.query(Log)
        .filter(Log.source_ip == source_ip)
        .order_by(Log.timestamp.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

    return {
        "count": len(logs),
        "logs": [log_to_dict(log) for log in logs],
    }


# ============================================================
# GET ALERTS
# ============================================================

@router.get("/alerts")
def get_alerts(
    db: Session = Depends(get_db)
):
    """
    Return alerts.

    Alerts are owned by the detection component, so this
    endpoint safely returns whatever exists in the alerts table.
    """

    alerts = (
        db.query(Alert)
        .order_by(Alert.id.desc())
        .all()
    )

    result = []

    for alert in alerts:
        result.append({
            "id": alert.id,
            "severity": getattr(alert, "severity", None),
            "source_log_id": getattr(alert, "source_log_id", None),
            "hostname": getattr(alert, "hostname", None),
            "source_ip": getattr(alert, "source_ip", None),
            "alert_type": getattr(alert, "alert_type", None),
            "rule_triggered": getattr(alert, "rule_triggered", None),
            "status": getattr(alert, "status", None),
            "triggered_at": getattr(alert, "triggered_at", None),
            "created_at": getattr(alert, "created_at", None),
        })

    return {
        "count": len(result),
        "alerts": result,
    }


# ============================================================
# GET SINGLE ALERT
# ============================================================

@router.get("/alerts/{alert_id}")
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db)
):
    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_id)
        .first()
    )

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail=f"Alert {alert_id} not found"
        )

    return {
        "id": alert.id,
        "severity": getattr(alert, "severity", None),
        "source_log_id": getattr(alert, "source_log_id", None),
        "hostname": getattr(alert, "hostname", None),
        "source_ip": getattr(alert, "source_ip", None),
        "alert_type": getattr(alert, "alert_type", None),
        "rule_triggered": getattr(alert, "rule_triggered", None),
        "status": getattr(alert, "status", None),
        "triggered_at": getattr(alert, "triggered_at", None),
        "created_at": getattr(alert, "created_at", None),
        "updated_at": getattr(alert, "updated_at", None),
    }


# ============================================================
# UPDATE ALERT STATUS
# ============================================================

@router.patch("/alerts/{alert_id}")
def update_alert_status(
    alert_id: int,
    request: AlertStatusUpdate,
    db: Session = Depends(get_db)
):
    """
    Update the status of an alert.

    Allowed statuses:
    OPEN, ACKNOWLEDGED, RESOLVED, CLOSED
    """

    allowed_statuses = {
        "OPEN",
        "ACKNOWLEDGED",
        "RESOLVED",
        "CLOSED",
    }

    new_status = request.status.upper()

    if new_status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid alert status. Allowed: {sorted(allowed_statuses)}"
        )

    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_id)
        .first()
    )

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail=f"Alert {alert_id} not found"
        )

    alert.status = new_status

    if new_status == "ACKNOWLEDGED":
        alert.acknowledged_at = datetime.now(UTC)

    elif new_status in {"RESOLVED", "CLOSED"}:
        if alert.resolved_at is None:
            alert.resolved_at = datetime.now(UTC)

    db.commit()
    db.refresh(alert)

    return {
        "status": "success",
        "alert": {
            "id": alert.id,
            "severity": getattr(alert, "severity", None),
            "source_log_id": getattr(alert, "source_log_id", None),
            "hostname": getattr(alert, "hostname", None),
            "source_ip": getattr(alert, "source_ip", None),
            "alert_type": getattr(alert, "alert_type", None),
            "rule_triggered": getattr(alert, "rule_triggered", None),
            "status": getattr(alert, "status", None),
            "triggered_at": getattr(alert, "triggered_at", None),
            "acknowledged_at": getattr(alert, "acknowledged_at", None),
            "resolved_at": getattr(alert, "resolved_at", None),
            "created_at": getattr(alert, "created_at", None),
            "updated_at": getattr(alert, "updated_at", None),
        },
    }


# ============================================================
# STATISTICS
# ============================================================

@router.get("/stats")
def get_stats(
    db: Session = Depends(get_db)
):
    """
    Dashboard statistics.
    """

    total_logs = db.query(Log).count()

    failed_logins = (
        db.query(Log)
        .filter(Log.event_type == "FAILED_LOGIN")
        .count()
    )

    successful_logins = (
        db.query(Log)
        .filter(Log.event_type == "SUCCESSFUL_LOGIN")
        .count()
    )

    total_alerts = db.query(Alert).count()

    return {
        "total_logs": total_logs,
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "total_alerts": total_alerts,
    }


# ============================================================
# REPORTS
# ============================================================

@router.get("/reports/{report_id}")
def get_report(
    report_id: int,
    db: Session = Depends(get_db)
):
    """
    Return a report if it exists.

    Reporting is handled by another component, but the endpoint
    remains stable.
    """

    report = (
        db.query(Report)
        .filter(Report.id == report_id)
        .first()
    )

    if report is None:
        return {
            "id": report_id,
            "status": "NOT_AVAILABLE",
            "message": "Report details are provided by the reporting service.",
        }

    return {
        "id": report.id,
        "title": getattr(report, "title", None),
        "description": getattr(report, "description", None),
        "report_type": getattr(report, "report_type", None),
        "content": getattr(report, "content", None),
        "start_date": getattr(report, "start_date", None),
        "end_date": getattr(report, "end_date", None),
        "total_logs": getattr(report, "total_logs", None),
        "total_alerts": getattr(report, "total_alerts", None),
        "critical_alerts": getattr(report, "critical_alerts", None),
        "status": getattr(report, "status", None),
        "generated_by": getattr(report, "generated_by", None),
        "created_at": getattr(report, "created_at", None),
        "updated_at": getattr(report, "updated_at", None),
    }


# ============================================================
# THREAT INTELLIGENCE IMPORT
# ============================================================

@router.post("/updates/import")
def import_updates(
    request: Optional[ThreatIntelImportRequest] = None,
    db: Session = Depends(get_db),
):
    """
    Import threat-intelligence updates.

    The request body is optional so the original placeholder
    endpoint remains backwards compatible.
    """

    if request is None:
        return {
            "status": "accepted",
            "imported": 0,
            "message": (
                "Threat intelligence import is handled by the "
                "updates service."
            ),
        }

    imported = 0

    try:
        for item in request.updates:
            threat = ThreatIntel(
                threat_type=item.threat_type,
                threat_name=item.threat_name,
                description=item.description,
                ioc_type=item.ioc_type,
                ioc_value=item.ioc_value,
                severity=item.severity,
                confidence=item.confidence,
                source=item.source,
            )

            db.add(threat)
            imported += 1

        db.commit()

    except Exception:
        db.rollback()
        raise

    return {
        "status": "accepted",
        "imported": imported,
        "message": "Threat intelligence updates imported successfully.",
    }
