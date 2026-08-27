import pytest
from datetime import datetime

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.log_ingestion.main import app
from backend.log_ingestion.database import Base, get_db
from backend.log_ingestion.parser import parse_log


TEST_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=test_engine,
)


@pytest.fixture(autouse=True)
def test_database():
    Base.metadata.create_all(bind=test_engine)

    try:
        yield
    finally:
        Base.metadata.drop_all(bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()

    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)


# ============================================================
# HEALTH / STATS
# ============================================================

def test_health():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_stats():
    response = client.get("/stats")

    assert response.status_code == 200

    data = response.json()

    assert "total_logs" in data
    assert "failed_logins" in data
    assert "successful_logins" in data
    assert "total_alerts" in data

    assert isinstance(data["total_logs"], int)
    assert isinstance(data["failed_logins"], int)
    assert isinstance(data["successful_logins"], int)
    assert isinstance(data["total_alerts"], int)


# ============================================================
# PARSER TESTS
# ============================================================

def test_parse_failed_login():
    raw_log = (
        "Aug 26 23:30:01 server "
        "sshd[2000]: Failed password for testuser "
        "from 10.0.0.99 port 6001"
    )

    result = parse_log(raw_log)

    assert isinstance(result["timestamp"], datetime)
    assert result["source_ip"] == "10.0.0.99"
    assert result["hostname"] == "server"
    assert result["event_type"] == "FAILED_LOGIN"
    assert result["username"] == "testuser"
    assert result["severity"] == "HIGH"
    assert result["raw_log"] == raw_log


def test_parse_successful_login():
    raw_log = (
        "Aug 26 23:35:01 server "
        "sshd[2001]: Accepted password for alice "
        "from 10.0.0.50 port 2200"
    )

    result = parse_log(raw_log)

    assert isinstance(result["timestamp"], datetime)
    assert result["source_ip"] == "10.0.0.50"
    assert result["hostname"] == "server"
    assert result["event_type"] == "SUCCESSFUL_LOGIN"
    assert result["username"] == "alice"
    assert result["severity"] == "INFO"
    assert result["raw_log"] == raw_log


def test_parse_extracts_source_ip():
    raw_log = (
        "Aug 26 23:40:01 server "
        "sshd[2002]: Failed password for admin "
        "from 192.168.1.25 port 5000"
    )

    result = parse_log(raw_log)

    assert result["source_ip"] == "192.168.1.25"


def test_parse_rejects_malformed_log():
    malformed_log = "this is not a valid ssh log"

    with pytest.raises(ValueError, match="Unsupported or malformed log format"):
        parse_log(malformed_log)


# ============================================================
# INGESTION / RETRIEVAL
# ============================================================

def test_ingest_log():
    raw_log = (
        "Aug 26 23:45:01 server "
        "sshd[2003]: Failed password for ingesttest "
        "from 10.0.0.88 port 6100"
    )

    response = client.post(
        "/logs/ingest",
        json={"logs": [raw_log]},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "success"
    assert data["ingested"] == 1
    assert data["failed"] == 0
    assert len(data["log_ids"]) == 1
    assert data["log_ids"][0] > 0

    assert data["results"][0]["status"] == "stored"
    assert data["results"][0]["log"]["source_ip"] == "10.0.0.88"
    assert data["results"][0]["log"]["username"] == "ingesttest"


def test_get_log_after_ingestion():
    raw_log = (
        "Aug 26 23:46:01 server "
        "sshd[2004]: Failed password for retrievaltest "
        "from 10.0.0.89 port 6200"
    )

    ingest_response = client.post(
        "/logs/ingest",
        json={"logs": [raw_log]},
    )

    assert ingest_response.status_code == 200

    log_id = ingest_response.json()["log_ids"][0]

    response = client.get(f"/logs/{log_id}")

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == log_id
    assert data["source_ip"] == "10.0.0.89"
    assert data["username"] == "retrievaltest"
    assert data["event_type"] == "FAILED_LOGIN"
def test_brute_force_detection():
    logs = [
        (
            "Aug 26 23:50:01 server "
            "sshd[3001]: Failed password for attacker "
            "from 10.0.0.77 port 6001"
        ),
        (
            "Aug 26 23:51:01 server "
            "sshd[3002]: Failed password for attacker "
            "from 10.0.0.77 port 6002"
        ),
        (
            "Aug 26 23:52:01 server "
            "sshd[3003]: Failed password for attacker "
            "from 10.0.0.77 port 6003"
        ),
    ]

    response = client.post(
        "/logs/ingest",
        json={"logs": logs},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "success"
    assert data["ingested"] == 3
    assert data["failed"] == 0

    assert len(data["alert_ids"]) == 1
    assert data["alert_ids"][0] > 0

    alert_id = data["alert_ids"][0]

    alert_response = client.get(f"/alerts/{alert_id}")

    assert alert_response.status_code == 200

    alert = alert_response.json()

    assert alert["id"] == alert_id
    assert alert["severity"] == "HIGH"
    assert alert["source_ip"] == "10.0.0.77"
    assert alert["alert_type"] == "brute_force"
    assert alert["status"] == "OPEN"
    assert "3 failed SSH logins" in alert["rule_triggered"]
def test_alert_lifecycle():
    logs = [
        (
            "Aug 26 23:55:01 server "
            "sshd[4001]: Failed password for lifecycle "
            "from 10.0.0.66 port 7001"
        ),
        (
            "Aug 26 23:56:01 server "
            "sshd[4002]: Failed password for lifecycle "
            "from 10.0.0.66 port 7002"
        ),
        (
            "Aug 26 23:57:01 server "
            "sshd[4003]: Failed password for lifecycle "
            "from 10.0.0.66 port 7003"
        ),
    ]

    response = client.post(
        "/logs/ingest",
        json={"logs": logs},
    )

    assert response.status_code == 200

    alert_id = response.json()["alert_ids"][0]

    # OPEN
    response = client.get(f"/alerts/{alert_id}")
    assert response.status_code == 200
    assert response.json()["status"] == "OPEN"

    # ACKNOWLEDGED
    response = client.patch(
        f"/alerts/{alert_id}",
        json={"status": "ACKNOWLEDGED"},
    )

    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "success"
    assert data["alert"]["status"] == "ACKNOWLEDGED"
    assert data["alert"]["acknowledged_at"] is not None
    assert data["alert"]["resolved_at"] is None

    # RESOLVED
    response = client.patch(
        f"/alerts/{alert_id}",
        json={"status": "RESOLVED"},
    )

    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "success"
    assert data["alert"]["status"] == "RESOLVED"
    assert data["alert"]["acknowledged_at"] is not None
    assert data["alert"]["resolved_at"] is not None

    # Verify persisted state
    response = client.get(f"/alerts/{alert_id}")

    assert response.status_code == 200

    alert = response.json()

    assert alert["status"] == "RESOLVED"

def test_cannot_reopen_resolved_alert():
    logs = [
        (
            "Aug 27 10:00:01 server "
            "sshd[9001]: Failed password for lifecycle2 "
            "from 10.0.0.200 port 8001"
        ),
        (
            "Aug 27 10:01:01 server "
            "sshd[9002]: Failed password for lifecycle2 "
            "from 10.0.0.200 port 8002"
        ),
        (
            "Aug 27 10:02:01 server "
            "sshd[9003]: Failed password for lifecycle2 "
            "from 10.0.0.200 port 8003"
        ),
    ]

    response = client.post(
        "/logs/ingest",
        json={"logs": logs},
    )

    assert response.status_code == 200

    alert_id = response.json()["alert_ids"][0]

    response = client.patch(
        f"/alerts/{alert_id}",
        json={"status": "ACKNOWLEDGED"},
    )
    assert response.status_code == 200

    response = client.patch(
        f"/alerts/{alert_id}",
        json={"status": "RESOLVED"},
    )
    assert response.status_code == 200
    assert response.json()["alert"]["status"] == "RESOLVED"
    assert response.json()["alert"]["resolved_at"] is not None

    response = client.patch(
        f"/alerts/{alert_id}",
        json={"status": "ACKNOWLEDGED"},
    )

    assert response.status_code == 400
    assert "Cannot move alert" in response.json()["detail"]

    response = client.get(f"/alerts/{alert_id}")
    assert response.status_code == 200

    alert = response.json()
    assert alert["status"] == "RESOLVED"
    assert alert["resolved_at"] is not None


def test_get_report_not_available():
    response = client.get("/reports/99999")

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == 99999
    assert data["status"] == "NOT_AVAILABLE"
    assert data["message"] == (
        "Report details are provided by the reporting service."
    )


def test_get_existing_report():
    from backend.log_ingestion.models import Report

    db = TestingSessionLocal()

    try:
        report = Report(
            title="Daily Security Summary",
            description="Test security report",
            report_type="daily_summary",
            content='{"summary":"test"}',
            total_logs=10,
            total_alerts=2,
            critical_alerts=0,
            status="FINALIZED",
            generated_by="test",
        )

        db.add(report)
        db.commit()
        db.refresh(report)

        report_id = report.id
    finally:
        db.close()

    response = client.get(f"/reports/{report_id}")

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == report_id
    assert data["title"] == "Daily Security Summary"
    assert data["description"] == "Test security report"
    assert data["report_type"] == "daily_summary"
    assert data["content"] == '{"summary":"test"}'
    assert data["total_logs"] == 10
    assert data["total_alerts"] == 2
    assert data["critical_alerts"] == 0
    assert data["status"] == "FINALIZED"
    assert data["generated_by"] == "test"
def test_updates_import_offline_package():
    response = client.post("/updates/import")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "accepted"
    assert data["imported"] == 1
    assert data["message"] == (
        "Verified offline threat intelligence updates imported successfully."
    )
def test_get_threat_intel():
    from backend.log_ingestion.models import ThreatIntel

    db = TestingSessionLocal()

    try:
        threat = ThreatIntel(
            threat_type="malware",
            threat_name="Test Malware",
            description="Test threat intelligence record",
            ioc_type="ip",
            ioc_value="10.10.10.10",
            severity="HIGH",
            confidence=0.95,
            source="test-feed",
        )

        db.add(threat)
        db.commit()
        db.refresh(threat)

        threat_id = threat.id
    finally:
        db.close()

    response = client.get("/threat-intel")

    assert response.status_code == 200

    data = response.json()

    assert data["count"] == 1
    assert len(data["threat_intel"]) == 1
    assert data["threat_intel"][0]["id"] == threat_id
    assert data["threat_intel"][0]["ioc_type"] == "ip"
    assert data["threat_intel"][0]["ioc_value"] == "10.10.10.10"
    assert data["threat_intel"][0]["severity"] == "HIGH"


def test_get_threat_intel_by_id():
    from backend.log_ingestion.models import ThreatIntel

    db = TestingSessionLocal()

    try:
        threat = ThreatIntel(
            threat_type="vulnerability",
            threat_name="Test Vulnerability",
            description="Test vulnerability",
            ioc_type="hash",
            ioc_value="abcdef123456",
            severity="CRITICAL",
            confidence=0.99,
            source="test-feed",
        )

        db.add(threat)
        db.commit()
        db.refresh(threat)

        threat_id = threat.id
    finally:
        db.close()

    response = client.get(f"/threat-intel/{threat_id}")

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == threat_id
    assert data["threat_type"] == "vulnerability"
    assert data["threat_name"] == "Test Vulnerability"
    assert data["ioc_type"] == "hash"
    assert data["ioc_value"] == "abcdef123456"
    assert data["severity"] == "CRITICAL"
    assert data["confidence"] == 0.99


def test_get_missing_threat_intel():
    response = client.get("/threat-intel/99999")

    assert response.status_code == 404
    assert response.json()["detail"] == (
        "Threat intelligence 99999 not found"
    )
def test_generate_report():
    from backend.log_ingestion.models import Report

    response = client.post("/reports/generate")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "success"

    report = data["report"]

    assert report["title"] == "Daily Security Summary"
    assert report["description"] == (
        "Generated security summary from the local detection engine."
    )
    assert report["report_type"] == "daily_summary"
    assert report["status"] == "FINALIZED"
    assert report["generated_by"] == "detection-engine"

    # Verify the generated report contains the current statistics.
    assert report["total_logs"] == 0
    assert report["total_alerts"] == 0
    assert report["critical_alerts"] == 0

    # Verify the report was actually persisted.
    db = TestingSessionLocal()

    try:
        saved_report = (
            db.query(Report)
            .filter(Report.id == report["id"])
            .first()
        )

        assert saved_report is not None
        assert saved_report.title == "Daily Security Summary"
        assert saved_report.report_type == "daily_summary"
        assert saved_report.status == "FINALIZED"
    finally:
        db.close()

    # Verify the persisted report can be retrieved through the API.
    response = client.get(f"/reports/{report['id']}")

    assert response.status_code == 200

    retrieved = response.json()

    assert retrieved["id"] == report["id"]
    assert retrieved["title"] == "Daily Security Summary"
    assert retrieved["report_type"] == "daily_summary"
    assert retrieved["status"] == "FINALIZED"