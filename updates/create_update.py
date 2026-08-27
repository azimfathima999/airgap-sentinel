import hashlib
import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
INCOMING_DIR = BASE_DIR / "incoming"

UPDATE_FILE = INCOMING_DIR / "update.json"
MANIFEST_FILE = INCOMING_DIR / "manifest.json"


UPDATE_DATA = {
    "updates": [
        {
            "threat_type": "malware",
            "threat_name": "Member4-Test-Malicious-IP",
            "description": "Offline threat-intelligence update for Member 4 demonstration.",
            "ioc_type": "ip",
            "ioc_value": "10.0.0.99",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "source": "offline-update-demo",
        }
    ]
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(8192), b""):
            digest.update(chunk)

    return digest.hexdigest()


def main():
    INCOMING_DIR.mkdir(parents=True, exist_ok=True)

    UPDATE_FILE.write_text(
        json.dumps(UPDATE_DATA, indent=2),
        encoding="utf-8",
    )

    file_hash = sha256_file(UPDATE_FILE)

    manifest = {
        "algorithm": "SHA-256",
        "file": UPDATE_FILE.name,
        "sha256": file_hash,
    }

    MANIFEST_FILE.write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )

    print(f"Created: {UPDATE_FILE}")
    print(f"Created: {MANIFEST_FILE}")
    print(f"SHA-256: {file_hash}")


if __name__ == "__main__":
    main()
