import hashlib
import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
INCOMING_DIR = BASE_DIR / "incoming"
VERIFIED_DIR = BASE_DIR / "verified"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(8192), b""):
            digest.update(chunk)

    return digest.hexdigest()


def verify_update() -> bool:
    update_file = INCOMING_DIR / "update.json"
    manifest_file = INCOMING_DIR / "manifest.json"

    if not update_file.exists():
        print("REJECTED: update.json not found")
        return False

    if not manifest_file.exists():
        print("REJECTED: manifest.json not found")
        return False

    try:
        manifest = json.loads(
            manifest_file.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError:
        print("REJECTED: invalid manifest.json")
        return False

    expected_hash = manifest.get("sha256")
    algorithm = manifest.get("algorithm")

    if algorithm != "SHA-256":
        print("REJECTED: unsupported hash algorithm")
        return False

    if not expected_hash:
        print("REJECTED: SHA-256 hash missing")
        return False

    actual_hash = sha256_file(update_file)

    if actual_hash != expected_hash:
        print("REJECTED: SHA-256 hash mismatch")
        print(f"Expected: {expected_hash}")
        print(f"Actual:   {actual_hash}")
        return False

    try:
        json.loads(update_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print("REJECTED: invalid update.json")
        return False

    VERIFIED_DIR.mkdir(parents=True, exist_ok=True)

    verified_update = VERIFIED_DIR / "update.json"
    verified_manifest = VERIFIED_DIR / "manifest.json"

    verified_update.write_bytes(update_file.read_bytes())
    verified_manifest.write_bytes(manifest_file.read_bytes())

    print("VERIFIED: update package passed SHA-256 validation")
    print(f"SHA-256: {actual_hash}")
    print(f"Copied to: {VERIFIED_DIR}")

    return True


if __name__ == "__main__":
    raise SystemExit(0 if verify_update() else 1)
