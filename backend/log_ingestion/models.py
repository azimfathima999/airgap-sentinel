from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Float, JSON
from sqlalchemy.sql import func
from backend.log_ingestion.database import Base
from datetime import datetime, UTC
from enum import Enum

# Enums for log levels and severity
class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AlertStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"

# ===================== LOG MODEL =====================
class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)

    timestamp = Column(DateTime, nullable=False, index=True)

    source_ip = Column(String(45), nullable=True, index=True)
    hostname = Column(String(255), nullable=True, index=True)
    event_type = Column(String(255), nullable=False, index=True)
    username = Column(String(255), nullable=True, index=True)
    message = Column(Text, nullable=False)
    severity = Column(String(50), nullable=True, index=True)
    raw_log = Column(Text, nullable=False)

    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(
        DateTime,
        server_default=func.now(),
        onupdate=func.now()
    )


# ===================== ALERT MODEL =====================
class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)

    # Alert metadata
    title = Column(String(255), index=True)
    description = Column(Text)
    status = Column(String(50), index=True, default=AlertStatus.OPEN)  # OPEN, ACKNOWLEDGED, RESOLVED, CLOSED
    severity = Column(String(50), index=True)  # LOW, MEDIUM, HIGH, CRITICAL

    # Source information
    source_log_id = Column(Integer, nullable=True, index=True)  # Reference to triggering log
    hostname = Column(String(255), nullable=True, index=True)
    source_ip = Column(String(45), nullable=True, index=True)

    # Alert details
    alert_type = Column(String(255), nullable=True, index=True)  # e.g., brute_force, port_scan
    rule_triggered = Column(String(255), nullable=True)  # Which rule triggered this

    # Timestamps
    triggered_at = Column(DateTime, default=lambda: datetime.now(UTC).replace(tzinfo=None), index=True)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    # Additional fields
    extra_metadata = Column(Text, nullable=True)  # JSON string with additional context
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())




# ===================== THREAT INTELLIGENCE MODEL =====================
class ThreatIntel(Base):
    __tablename__ = "threat_intel"

    id = Column(Integer, primary_key=True, index=True)

    # Threat identification
    threat_type = Column(String(255), index=True)  # e.g., malware, exploit, vulnerability
    threat_name = Column(String(255), index=True)
    description = Column(Text)

    # Indicators of Compromise (IoCs)
    ioc_type = Column(String(50), nullable=True, index=True)  # ip, domain, hash, url
    ioc_value = Column(String(255), nullable=True, index=True)  # The actual IOC value

    # Severity and classification
    severity = Column(String(50), index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, nullable=True)  # 0.0 to 1.0

    # Source information
    source = Column(String(255), nullable=True)  # Where this threat intel came from

    # Timestamps
    first_seen = Column(DateTime, default=lambda: datetime.now(UTC).replace(tzinfo=None))
    last_seen = Column(DateTime, default=lambda: datetime.now(UTC).replace(tzinfo=None))

    # Additional extra_metadata
    extra_metadata = Column(Text, nullable=True)  # JSON string with additional context
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())




# ===================== INCIDENT RESPONSE MODEL =====================
class Response(Base):
    __tablename__ = "responses"

    id = Column(Integer, primary_key=True, index=True)

    # Response metadata
    alert_id = Column(Integer, nullable=True, index=True)  # Reference to alert
    response_type = Column(String(255), index=True)  # e.g., block_ip, isolate_host, escalate

    # Response details
    description = Column(Text)
    status = Column(String(50), index=True, default="PENDING")  # PENDING, EXECUTING, COMPLETED, FAILED

    # Actions taken
    action_command = Column(Text, nullable=True)  # Command/action executed
    action_result = Column(Text, nullable=True)  # Result of the action

    # Timestamps
    initiated_at = Column(DateTime, default=lambda: datetime.now(UTC).replace(tzinfo=None))
    completed_at = Column(DateTime, nullable=True)

    # Audit trail
    initiated_by = Column(String(255), nullable=True)  # User or system that initiated
    notes = Column(Text, nullable=True)

    extra_metadata = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())




# ===================== REPORT MODEL =====================
class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)

    # Report metadata
    title = Column(String(255), index=True)
    description = Column(Text)
    report_type = Column(String(255), nullable=True, index=True)  # e.g., daily_summary, incident, threat_analysis

    # Report content
    content = Column(Text)  # Full report content (JSON or markdown)

    # Date range
    start_date = Column(DateTime, index=True)
    end_date = Column(DateTime, index=True)

    # Report statistics
    total_logs = Column(Integer, nullable=True)
    total_alerts = Column(Integer, nullable=True)
    critical_alerts = Column(Integer, nullable=True)

    # Status
    status = Column(String(50), default="DRAFT")  # DRAFT, FINALIZED, SENT, ARCHIVED

    # Audit fields
    generated_by = Column(String(255), nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
