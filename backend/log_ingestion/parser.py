import re
from datetime import datetime


FAILED_LOGIN_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"sshd\[\d+\]:\s+"
    r"Failed password for (?P<username>\S+)\s+"
    r"from (?P<source_ip>\S+)\s+port \d+$"
)

SUCCESSFUL_LOGIN_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"sshd\[\d+\]:\s+"
    r"Accepted password for (?P<username>\S+)\s+"
    r"from (?P<source_ip>\S+)\s+port \d+$"
)


def parse_log(raw_log: str) -> dict:
    """
    Parse a supported SSH syslog line into a structured event.
    Raises ValueError when the log format is unsupported.
    """

    raw_log = raw_log.strip()

    match = FAILED_LOGIN_PATTERN.match(raw_log)
    if match:
        data = match.groupdict()
        timestamp = datetime.strptime(
            data["timestamp"],
            "%b %d %H:%M:%S"
        ).replace(year=datetime.now().year)

        return {
            "timestamp": timestamp,
            "source_ip": data["source_ip"],
            "hostname": data["hostname"],
            "event_type": "FAILED_LOGIN",
            "username": data["username"],
            "message": (
                f"Failed password for {data['username']} "
                f"from {data['source_ip']}"
            ),
            "severity": "HIGH",
            "raw_log": raw_log,
        }

    match = SUCCESSFUL_LOGIN_PATTERN.match(raw_log)
    if match:
        data = match.groupdict()
        timestamp = datetime.strptime(
            data["timestamp"],
            "%b %d %H:%M:%S"
        ).replace(year=datetime.now().year)

        return {
            "timestamp": timestamp,
            "source_ip": data["source_ip"],
            "hostname": data["hostname"],
            "event_type": "SUCCESSFUL_LOGIN",
            "username": data["username"],
            "message": (
                f"Accepted password for {data['username']} "
                f"from {data['source_ip']}"
            ),
            "severity": "INFO",
            "raw_log": raw_log,
        }

    raise ValueError("Unsupported or malformed log format")
