"""
Data models for the detection engine.

These are deliberately simple (dataclasses -> dict) so they serialize
cleanly to JSON for the /alerts API and are easy to explain to judges.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import itertools

_alert_id_counter = itertools.count(1)
_response_id_counter = itertools.count(1)


def _next_alert_id() -> str:
    return f"ALERT-{next(_alert_id_counter):04d}"


def _next_response_id() -> str:
    return f"RESP-{next(_response_id_counter):04d}"


@dataclass
class LogEvent:
    """A structured log event received from Member 1's ingestion layer."""
    event_type: str          # e.g. "LOGIN_FAILURE", "LOGIN_SUCCESS"
    source_ip: str
    timestamp: datetime
    username: Optional[str] = None
    raw: Optional[dict] = None  # original payload, for traceability

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "source_ip": self.source_ip,
            "timestamp": self.timestamp.isoformat(),
            "username": self.username,
        }


@dataclass
class Alert:
    """
    Matches the alert format defined in section 5 of the spec:
    {
      "rule_id": "RULE-001",
      "title": "Repeated failed login attempts",
      "severity": "HIGH",
      "source_ip": "10.0.0.25",
      "reason": "5 failed logins from the same IP within 5 minutes",
      "status": "OPEN"
    }
    """
    rule_id: str
    title: str
    severity: str             # LOW | MEDIUM | HIGH | CRITICAL
    source_ip: str
    reason: str
    status: str = "OPEN"
    alert_id: str = field(default_factory=_next_alert_id)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "reason": self.reason,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class ResponseRecord:
    """
    Audit record for a *simulated* response action (section 6).
    Never touches the real OS/firewall/accounts/network.
    """
    alert_id: str
    action: str                # e.g. BLOCK_IP_SIMULATED
    description: str           # human-readable audit text
    response_id: str = field(default_factory=_next_response_id)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "response_id": self.response_id,
            "alert_id": self.alert_id,
            "action": self.action,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
        }
