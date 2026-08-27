"""
Tests matching section 8 ("Tests") of the spec, one test per bullet:

- Four failed logins do not trigger RULE-001.
- Five failed logins within five minutes trigger one HIGH alert.
- Five failed logins spread beyond the configured window do not trigger
  the threshold rule.
- An imported malicious IP triggers the threat-intelligence rule.
- A response record is created for every generated alert.
- Normal login events do not generate false alerts.
- Alert explanation clearly states the evidence.
"""

import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from detection_engine import DetectionEngine, LogEvent

ATTACK_IP = "10.0.0.25"
THREAT_INTEL_IP = "10.0.0.99"


@pytest.fixture
def engine():
    return DetectionEngine()


def _failure(ip: str, ts: datetime, username: str = "alice") -> LogEvent:
    return LogEvent(event_type="LOGIN_FAILURE", source_ip=ip, timestamp=ts, username=username)


def _success(ip: str, ts: datetime, username: str = "alice") -> LogEvent:
    return LogEvent(event_type="LOGIN_SUCCESS", source_ip=ip, timestamp=ts, username=username)


def test_four_failed_logins_do_not_trigger_rule_001(engine):
    base = datetime(2026, 8, 27, 10, 0, 0)  # inside normal hours, avoids RULE-002 noise
    for i in range(4):
        alerts = engine.process_event(_failure(ATTACK_IP, base + timedelta(seconds=i * 10)))
    assert alerts == []
    assert engine.get_alerts() == []


def test_five_failed_logins_within_five_minutes_trigger_one_high_alert(engine):
    base = datetime(2026, 8, 27, 10, 0, 0)
    all_alerts = []
    for i in range(5):
        all_alerts += engine.process_event(_failure(ATTACK_IP, base + timedelta(minutes=i)))

    high_alerts = [a for a in engine.get_alerts() if a["rule_id"] == "RULE-001"]
    assert len(high_alerts) == 1
    assert high_alerts[0]["severity"] == "HIGH"
    assert high_alerts[0]["source_ip"] == ATTACK_IP


def test_five_failed_logins_spread_beyond_window_do_not_trigger(engine):
    base = datetime(2026, 8, 27, 10, 0, 0)
    # 5 events, 3 minutes apart -> 5th event is 12 minutes after the 1st,
    # so no rolling 5-minute window ever contains 5 events.
    for i in range(5):
        engine.process_event(_failure(ATTACK_IP, base + timedelta(minutes=i * 3)))

    rule_001_alerts = [a for a in engine.get_alerts() if a["rule_id"] == "RULE-001"]
    assert rule_001_alerts == []


def test_imported_malicious_ip_triggers_threat_intel_rule(engine):
    engine.import_threat_intel([
        {
            "indicator": THREAT_INTEL_IP,
            "indicator_type": "ip",
            "confidence": "high",
            "source": "offline-feed-v1",
        }
    ])
    ts = datetime(2026, 8, 27, 10, 0, 0)
    alerts = engine.process_event(_success(THREAT_INTEL_IP, ts))

    rule_003 = [a for a in alerts if a.rule_id == "RULE-003"]
    assert len(rule_003) == 1
    assert rule_003[0].severity == "CRITICAL"
    assert rule_003[0].source_ip == THREAT_INTEL_IP


def test_response_record_created_for_every_alert(engine):
    base = datetime(2026, 8, 27, 10, 0, 0)
    for i in range(5):
        engine.process_event(_failure(ATTACK_IP, base + timedelta(minutes=i)))

    assert len(engine.get_alerts()) == len(engine.get_responses())
    assert len(engine.get_responses()) >= 1
    for response in engine.get_responses():
        assert response["action"] == "BLOCK_IP_SIMULATED"
        assert ATTACK_IP in response["description"]


def test_normal_login_events_do_not_generate_false_alerts(engine):
    ts = datetime(2026, 8, 27, 14, 30, 0)  # inside normal hours, single event
    alerts = engine.process_event(_success("10.0.0.1", ts))
    assert alerts == []
    assert engine.get_alerts() == []


def test_alert_explanation_states_the_evidence(engine):
    base = datetime(2026, 8, 27, 10, 0, 0)
    for i in range(5):
        engine.process_event(_failure(ATTACK_IP, base + timedelta(minutes=i)))

    alert = engine.get_alerts()[0]
    assert "5" in alert["reason"]
    assert "5 minutes" in alert["reason"]
    assert ATTACK_IP in alert["source_ip"]


def test_odd_hours_login_triggers_rule_002(engine):
    ts = datetime(2026, 8, 27, 2, 15, 0)  # 2:15 AM, outside 06:00-22:00
    alerts = engine.process_event(_success("10.0.0.50", ts))
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-002"
    assert alerts[0].severity == "MEDIUM"


def test_severity_meanings_available_for_member_3_handoff():
    from detection_engine import SEVERITY_MEANINGS
    for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        assert level in SEVERITY_MEANINGS
