"""
Demo script for the hackathon finale — uses the exact dataset from
section 9 of the spec:

  - Behavior-based detection: 5 failed logins from 10.0.0.25
  - Indicator-based detection: known-bad IP 10.0.0.99 from threat intel

Run: python demo.py
"""

import json
from datetime import datetime, timedelta

from detection_engine import DetectionEngine, LogEvent, SEVERITY_MEANINGS

ATTACK_IP = "10.0.0.25"
THREAT_INTEL_IP = "10.0.0.99"


def main():
    engine = DetectionEngine()

    # --- Load Member 4's offline threat-intel list -----------------------
    engine.import_threat_intel([
        {
            "indicator": THREAT_INTEL_IP,
            "indicator_type": "ip",
            "confidence": "high",
            "source": "offline-feed-demo",
        }
    ])

    print("=== Demo 1: Behavior-based detection (RULE-001) ===")
    base = datetime.now().replace(hour=10, minute=0, second=0, microsecond=0)
    for i in range(5):
        event = LogEvent(
            event_type="LOGIN_FAILURE",
            source_ip=ATTACK_IP,
            timestamp=base + timedelta(minutes=i),
            username="admin",
        )
        alerts = engine.process_event(event)
        print(f"  Login failure #{i + 1} from {ATTACK_IP} -> "
              f"{len(alerts)} new alert(s)")

    print("\n=== Demo 2: Indicator-based detection (RULE-003) ===")
    event = LogEvent(
        event_type="LOGIN_SUCCESS",
        source_ip=THREAT_INTEL_IP,
        timestamp=datetime.now(),
        username="svc-account",
    )
    engine.process_event(event)

    print("\n=== Alerts (what /alerts would return) ===")
    print(json.dumps(engine.get_alerts(), indent=2, default=str))

    print("\n=== Simulated response audit trail ===")
    print(json.dumps(engine.get_responses(), indent=2, default=str))

    print("\n=== Severity meanings (for Member 3's dashboard) ===")
    for level, meaning in SEVERITY_MEANINGS.items():
        print(f"  {level}: {meaning}")


if __name__ == "__main__":
    main()
