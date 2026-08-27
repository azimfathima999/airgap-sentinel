from datetime import datetime, timedelta, UTC
import re
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.log_ingestion.database import get_db
from backend.log_ingestion.models import (
    Log,
    Alert,
    Report,
    ThreatIntel,
    Response,
)
from backend.log_ingestion.schemas import ThreatIntelImportRequest


router = APIRouter(tags=["logs"])


# ============================================================
# CONFIGURATION
# ============================================================

FAILED_LOGIN_THRESHOLD = 3
FAILED_LOGIN_WINDOW_MINUTES = 5

NORMAL_LOGIN_START = 6
NORMAL_LOGIN_END = 22


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
    Parse an SSH/syslog line into structured fields.
    """

    if not raw_log or not raw_log.strip():
        raise ValueError("Log line is empty")

    raw_log = raw_log.strip()

    match = SYSLOG_PATTERN.match(raw_log)

    if not match:
        raise ValueError("Unsupported or malformed log format")

    month = match.group("month")
    day = match.group("day")
    time = match.group("time")
    hostname = match.group("hostname")
    service = match.group("service")

    message = re.sub(
        r"\s+",
        " ",
        match.group("message"),
    ).strip()

    # Syslog lines do not contain a year.
    # Current prototype year is 2026.
    timestamp = datetime.strptime(
        f"2026 {month} {day} {time}",
        "%Y %b %d %H:%M:%S",
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
# SERIALIZATION HELPERS
# ============================================================

def log_to_dict(log: Log) -> dict:
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


def alert_to_dict(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "title": getattr(alert, "title", None),
        "description": getattr(alert, "description", None),
        "severity": getattr(alert, "severity", None),
        "status": getattr(alert, "status", None),
        "source_log_id": getattr(alert, "source_log_id", None),
        "hostname": getattr(alert, "hostname", None),
        "source_ip": getattr(alert, "source_ip", None),
        "alert_type": getattr(alert, "alert_type", None),
        "rule_triggered": getattr(alert, "rule_triggered", None),
        "triggered_at": getattr(alert, "triggered_at", None),
        "acknowledged_at": getattr(alert, "acknowledged_at", None),
        "resolved_at": getattr(alert, "resolved_at", None),
        "created_at": getattr(alert, "created_at", None),
        "updated_at": getattr(alert, "updated_at", None),
    }


def response_to_dict(response: Response) -> dict:
    return {
        "id": response.id,
        "alert_id": response.alert_id,
        "response_type": response.response_type,
        "description": response.description,
        "status": response.status,
        "action_command": response.action_command,
        "action_result": response.action_result,
        "initiated_at": response.initiated_at,
        "completed_at": response.completed_at,
        "initiated_by": response.initiated_by,
        "notes": response.notes,
        "extra_metadata": response.extra_metadata,
        "created_at": response.created_at,
        "updated_at": response.updated_at,
    }


def threat_intel_to_dict(threat: ThreatIntel) -> dict:
    return {
        "id": threat.id,
        "threat_type": threat.threat_type,
        "threat_name": threat.threat_name,
        "description": threat.description,
        "ioc_type": threat.ioc_type,
        "ioc_value": threat.ioc_value,
        "severity": threat.severity,
        "confidence": threat.confidence,
        "source": threat.source,
        "first_seen": threat.first_seen,
        "last_seen": threat.last_seen,
        "created_at": threat.created_at,
        "updated_at": threat.updated_at,
    }


# ============================================================
# RULE 001 — BRUTE FORCE
# ============================================================

def detect_brute_force(db: Session, log: Log):
    """
    RULE-001

    Five or more failed logins from the same source IP
    within five minutes produce a HIGH alert.

    This matches Member 2's detection-engine specification.
    """

    if log.event_type != "FAILED_LOGIN":
        return None

    if not log.source_ip:
        return None

    window_start = (
        log.timestamp
        - timedelta(minutes=FAILED_LOGIN_WINDOW_MINUTES)
    )

    failed_count = (
        db.query(Log)
        .filter(
            Log.source_ip == log.source_ip,
            Log.event_type == "FAILED_LOGIN",
            Log.timestamp > window_start,
            Log.timestamp <= log.timestamp,
        )
        .count()
    )

    if failed_count < FAILED_LOGIN_THRESHOLD:
        return None

    # Do not create duplicate OPEN brute-force alerts
    # for the same source IP.
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
        title="Repeated failed login attempts",
        description=(
            f"{failed_count} failed login attempts from the same "
            f"IP ({log.source_ip}) within "
            f"{FAILED_LOGIN_WINDOW_MINUTES} minutes."
        ),
        status="OPEN",
        severity="HIGH",
        source_log_id=log.id,
        hostname=log.hostname,
        source_ip=log.source_ip,
        alert_type="brute_force",
        rule_triggered=(
    f"{FAILED_LOGIN_THRESHOLD} failed SSH logins from same IP "
    f"within {FAILED_LOGIN_WINDOW_MINUTES} minutes"
),
        triggered_at=log.timestamp,
    )

    db.add(alert)
    db.flush()

    # Safe simulated response.
    response = Response(
        alert_id=alert.id,
        response_type="BLOCK_IP_SIMULATED",
        description=(
            f"IP {log.source_ip} marked as blocked "
            f"in simulated response policy."
        ),
        status="COMPLETED",
        completed_at=datetime.now(UTC),
        action_command=None,
        action_result=(
            "SIMULATED ONLY — no firewall, network, "
            "host, or account was modified."
        ),
        initiated_by="detection-engine",
        notes="Safe simulated response for RULE-001.",
    )

    db.add(response)
    db.flush()

    return alert


# ============================================================
# RULE 002 — ODD HOURS LOGIN
# ============================================================

def detect_odd_hours_login(db: Session, log: Log):
    """
    RULE-002

    Login outside configured normal hours produces
    a MEDIUM alert.

    Normal hours: 06:00 through 21:59.
    """


    if log.event_type != "SUCCESSFUL_LOGIN":
        return None

    hour = log.timestamp.hour

    if NORMAL_LOGIN_START <= hour < NORMAL_LOGIN_END:
        return None

    # Avoid duplicate odd-hours alerts for the same exact event.
    existing_alert = (
        db.query(Alert)
        .filter(
            Alert.source_log_id == log.id,
            Alert.alert_type == "odd_hours_login",
        )
        .first()
    )

    if existing_alert:
        return existing_alert

    alert = Alert(
        title="Login outside normal hours",
        description=(
            f"Login at {log.timestamp.strftime('%H:%M')} "
            f"occurred outside configured normal hours "
            f"({NORMAL_LOGIN_START:02d}:00-"
            f"{NORMAL_LOGIN_END:02d}:00)."
        ),
        status="OPEN",
        severity="MEDIUM",
        source_log_id=log.id,
        hostname=log.hostname,
        source_ip=log.source_ip,
        alert_type="odd_hours_login",
        rule_triggered=(
            "RULE-002: login outside configured normal hours"
        ),
        triggered_at=log.timestamp,
    )

    db.add(alert)
    db.flush()

    response = Response(
        alert_id=alert.id,
        response_type="FLAG_FOR_REVIEW",
        description="Event added to analyst review queue.",
        status="COMPLETED",
        completed_at=database.now(UTC),
        action_command=None,
        action_result=(
            "SIMULATED ONLY — event flagged for analyst review."
        ),
        initiated_by="detection-engine",
        notes="Safe simulated response for RULE-002.",
    )

    db.add(response)
    db.flush()

    return alert


# ============================================================
# RULE 003 — THREAT INTELLIGENCE MATCH
# ============================================================

def detect_threat_intel(db: Session, log: Log):
    """
    RULE-003

    If the source IP exists in the local threat-intelligence
    table, generate a CRITICAL alert.
    """

    if not log.source_ip:
        return None

    threat = (
        db.query(ThreatIntel)
        .filter(
            ThreatIntel.ioc_type == "ip",
            ThreatIntel.ioc_value == log.source_ip,
        )
        .first()
    )

    if threat is None:
        return None

    # Avoid duplicate threat-intel alerts for the same log.
    existing_alert = (
        db.query(Alert)
        .filter(
            Alert.source_log_id == log.id,
            Alert.alert_type == "threat_intel_match",
        )
        .first()
    )

    if existing_alert:
        return existing_alert

    confidence = threat.confidence

    if confidence is not None:
        confidence_text = str(confidence)
    else:
        confidence_text = "unknown"

    alert = Alert(
        title="Known malicious indicator match",
        description=(
            f"Source IP {log.source_ip} matches a known "
            f"malicious threat-intelligence indicator. "
            f"Source: {threat.source or 'unknown'}, "
            f"confidence: {confidence_text}."
        ),
        status="OPEN",
        severity="CRITICAL",
        source_log_id=log.id,
        hostname=log.hostname,
        source_ip=log.source_ip,
        alert_type="threat_intel_match",
        rule_triggered=(
            "RULE-003: source IP matches local threat intelligence"
        ),
        triggered_at=log.timestamp,
    )

    db.add(alert)
    db.flush()

    response = Response(
        alert_id=alert.id,
        response_type="ISOLATE_HOST_SIMULATED",
        description="Host isolation recommended and recorded.",
        status="COMPLETED",
        completed_at=datetime.now(UTC),
        action_command=None,
        action_result=(
            "SIMULATED ONLY — no host, network, or account "
            "was actually isolated."
        ),
        initiated_by="detection-engine",
        notes="Safe simulated response for RULE-003.",
    )

    db.add(response)
    db.flush()

    return alert


# ============================================================
# RUN ALL DETECTION RULES
# ============================================================

def run_detection_rules(db: Session, log: Log) -> List[Alert]:
    """
    Run all detection rules against one ingested event.

    RULE-003 is evaluated first because a known malicious
    indicator is immediately CRITICAL.
    """

    alerts = []

    # CRITICAL threat-intel match first.
    threat_alert = detect_threat_intel(db, log)

    if threat_alert:
        alerts.append(threat_alert)

    # Behavioral rules.
    brute_force_alert = detect_brute_force(db, log)

    if brute_force_alert:
        # Avoid returning the same alert twice.
        if brute_force_alert not in alerts:
            alerts.append(brute_force_alert)

    odd_hours_alert = detect_odd_hours_login(db, log)

    if odd_hours_alert:
        if odd_hours_alert not in alerts:
            alerts.append(odd_hours_alert)

    return alerts


# ============================================================
# INGEST LOGS
# ============================================================

@router.post("/logs/ingest")
def ingest_logs(
    request: IngestRequest,
    db: Session = Depends(get_db),
):
    """
    Ingest one or more raw SSH/syslog lines.

    Every successfully parsed log is stored in SQLite and
    passed through the detection rules.
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

            alerts = run_detection_rules(db, db_log)

            for alert in alerts:
                if alert.id not in alert_ids:
                    alert_ids.append(alert.id)

            stored_log_ids.append(db_log.id)

            results.append({
                "index": index,
                "status": "stored",
                "log": log_to_dict(db_log),
                "alerts_generated": [
                    alert_to_dict(alert)
                    for alert in alerts
                ],
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
    db: Session = Depends(get_db),
):
    """
    Batch version of /logs/ingest.
    """

    return ingest_logs(request, db)


# ============================================================
# GET ALL LOGS
# ============================================================

@router.get("/logs")
def get_logs(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    if skip < 0:
        raise HTTPException(
            status_code=400,
            detail="skip must be >= 0",
        )

    if limit < 1 or limit > 1000:
        raise HTTPException(
            status_code=400,
            detail="limit must be between 1 and 1000",
        )

    logs = (
        db.query(Log)
        .order_by(Log.timestamp.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

    return {
        "count": len(logs),
        "logs": [
            log_to_dict(log)
            for log in logs
        ],
    }


# ============================================================
# GET SINGLE LOG
# ============================================================

@router.get("/logs/{log_id}")
def get_log(
    log_id: int,
    db: Session = Depends(get_db),
):
    log = (
        db.query(Log)
        .filter(Log.id == log_id)
        .first()
    )

    if log is None:
        raise HTTPException(
            status_code=404,
            detail=f"Log {log_id} not found",
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
    db: Session = Depends(get_db),
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
        "logs": [
            log_to_dict(log)
            for log in logs
        ],
    }


# ============================================================
# GET ALERTS
# ============================================================

@router.get("/alerts")
def get_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Alert)

    if severity:
        query = query.filter(
            Alert.severity == severity.upper()
        )

    if status:
        query = query.filter(
            Alert.status == status.upper()
        )

    alerts = (
        query
        .order_by(Alert.id.desc())
        .all()
    )

    return {
        "count": len(alerts),
        "alerts": [
            alert_to_dict(alert)
            for alert in alerts
        ],
    }


# ============================================================
# GET SINGLE ALERT
# ============================================================

@router.get("/alerts/{alert_id}")
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
):
    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_id)
        .first()
    )

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail=f"Alert {alert_id} not found",
        )

    return alert_to_dict(alert)


# ============================================================
# UPDATE ALERT STATUS
# ============================================================

@router.patch("/alerts/{alert_id}")
def update_alert_status(
    alert_id: int,
    request: AlertStatusUpdate,
    db: Session = Depends(get_db),
):
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
            detail=(
                "Invalid alert status. Allowed: "
                f"{sorted(allowed_statuses)}"
            ),
        )

    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_id)
        .first()
    )

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail=f"Alert {alert_id} not found",
        )

    alert.status = new_status

    if new_status == "ACKNOWLEDGED":
        if alert.acknowledged_at is None:
            alert.acknowledged_at = datetime.now(UTC)

    elif new_status in {"RESOLVED", "CLOSED"}:
        if alert.resolved_at is None:
            alert.resolved_at = datetime.now(UTC)

    db.commit()
    db.refresh(alert)

    return {
        "status": "success",
        "alert": alert_to_dict(alert),
    }


# ============================================================
# RESPONSES
# ============================================================

@router.get("/responses")
def get_responses(
    db: Session = Depends(get_db),
):
    """
    Return simulated response audit records.

    No real firewall, host, account, or network action is
    performed by these records.
    """

    responses = (
        db.query(Response)
        .order_by(Response.id.desc())
        .all()
    )

    return {
        "count": len(responses),
        "responses": [
            response_to_dict(response)
            for response in responses
        ],
    }


# ============================================================
# STATISTICS
# ============================================================

@router.get("/stats")
def get_stats(
    db: Session = Depends(get_db),
):
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

    critical_alerts = (
        db.query(Alert)
        .filter(Alert.severity == "CRITICAL")
        .count()
    )

    high_alerts = (
        db.query(Alert)
        .filter(Alert.severity == "HIGH")
        .count()
    )

    medium_alerts = (
        db.query(Alert)
        .filter(Alert.severity == "MEDIUM")
        .count()
    )

    open_alerts = (
        db.query(Alert)
        .filter(Alert.status == "OPEN")
        .count()
    )

    threat_intel_count = db.query(ThreatIntel).count()

    return {
        "total_logs": total_logs,
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "open_alerts": open_alerts,
        "threat_intel_count": threat_intel_count,
        "detection_rules": {
            "RULE-001": (
                f"{FAILED_LOGIN_THRESHOLD} failed logins "
                f"within {FAILED_LOGIN_WINDOW_MINUTES} minutes"
            ),
            "RULE-002": (
                f"login outside {NORMAL_LOGIN_START:02d}:00-"
                f"{NORMAL_LOGIN_END:02d}:00"
            ),
            "RULE-003": (
                "source IP matches local threat intelligence"
            ),
        },
    }


# ============================================================
# REPORTS
# ============================================================
@router.post("/reports/generate")
def generate_report(
    db: Session = Depends(get_db),
):
    """
    Generate and persist a daily security summary report
    from the current database state.
    """

    total_logs = db.query(Log).count()
    total_alerts = db.query(Alert).count()

    critical_alerts = (
        db.query(Alert)
        .filter(Alert.severity == "CRITICAL")
        .count()
    )

    high_alerts = (
        db.query(Alert)
        .filter(Alert.severity == "HIGH")
        .count()
    )

    medium_alerts = (
        db.query(Alert)
        .filter(Alert.severity == "MEDIUM")
        .count()
    )

    open_alerts = (
        db.query(Alert)
        .filter(Alert.status == "OPEN")
        .count()
    )

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

    threat_intel_count = db.query(ThreatIntel).count()

    now = datetime.now(UTC).replace(tzinfo=None)

    content = {
        "summary": {
            "total_logs": total_logs,
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "medium_alerts": medium_alerts,
            "open_alerts": open_alerts,
            "failed_logins": failed_logins,
            "successful_logins": successful_logins,
            "threat_intel_count": threat_intel_count,
        },
        "detection_rules": {
            "RULE-001": (
                f"{FAILED_LOGIN_THRESHOLD} failed logins "
                f"within {FAILED_LOGIN_WINDOW_MINUTES} minutes"
            ),
            "RULE-002": (
                f"login outside {NORMAL_LOGIN_START:02d}:00-"
                f"{NORMAL_LOGIN_END:02d}:00"
            ),
            "RULE-003": (
                "source IP matches local threat intelligence"
            ),
        },
    }

    import json

    report = Report(
        title="Daily Security Summary",
        description="Generated security summary from the local detection engine.",
        report_type="daily_summary",
        content=json.dumps(content),
        total_logs=total_logs,
        total_alerts=total_alerts,
        critical_alerts=critical_alerts,
        status="FINALIZED",
        generated_by="detection-engine",
        start_date=None,
        end_date=now,
    )

    db.add(report)
    db.commit()
    db.refresh(report)

    return {
        "status": "success",
        "report": {
            "id": report.id,
            "title": report.title,
            "description": report.description,
            "report_type": report.report_type,
            "content": report.content,
            "total_logs": report.total_logs,
            "total_alerts": report.total_alerts,
            "critical_alerts": report.critical_alerts,
            "status": report.status,
            "generated_by": report.generated_by,
            "created_at": report.created_at,
            "updated_at": report.updated_at,
        },
    }
@router.get("/reports/{report_id}")
def get_report(
    report_id: int,
    db: Session = Depends(get_db),
):
    report = (
        db.query(Report)
        .filter(Report.id == report_id)
        .first()
    )

    if report is None:
        return {
            "id": report_id,
            "status": "NOT_AVAILABLE",
            "message": (
                "Report details are provided by the "
                "reporting service."
            ),
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
    Import threat-intelligence updates into the local database.

    This endpoint remains compatible with the existing
    ThreatIntelImportRequest schema.
    """

    if request is None:
        return {
            "status": "accepted",
            "imported": 0,
            "message": (
                "Threat intelligence import is handled by "
                "the updates service."
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
        "message": (
            "Threat intelligence updates imported successfully."
        ),
    }


# ============================================================
# THREAT INTELLIGENCE RETRIEVAL
# ============================================================

@router.get("/threat-intel")
def get_threat_intel(
    ioc_type: Optional[str] = None,
    ioc_value: Optional[str] = None,
    threat_type: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    query = db.query(ThreatIntel)

    if ioc_type:
        query = query.filter(
            ThreatIntel.ioc_type == ioc_type
        )

    if ioc_value:
        query = query.filter(
            ThreatIntel.ioc_value == ioc_value
        )

    if threat_type:
        query = query.filter(
            ThreatIntel.threat_type == threat_type
        )

    if severity:
        query = query.filter(
            ThreatIntel.severity == severity.upper()
        )

    if source:
        query = query.filter(
            ThreatIntel.source == source
        )

    threats = (
        query
        .order_by(ThreatIntel.id.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

    return {
        "count": len(threats),
        "threat_intel": [
            threat_intel_to_dict(threat)
            for threat in threats
        ],
    }


# ============================================================
# GET SINGLE THREAT INTELLIGENCE RECORD
# ============================================================

@router.get("/threat-intel/{threat_id}")
def get_threat_intel_item(
    threat_id: int,
    db: Session = Depends(get_db),
):
    threat = (
        db.query(ThreatIntel)
        .filter(ThreatIntel.id == threat_id)
        .first()
    )

    if threat is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Threat intelligence {threat_id} not found"
            ),
        )

    return threat_intel_to_dict(threat)
