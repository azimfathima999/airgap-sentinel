"""
updates_core.py
================
Shared logic for Airgap Sentinel's hardened, offline update mechanism.

This module is the single source of truth for:
  - creating a signed/hashed threat-intel update package
  - verifying a package against its manifest (SHA-256)
  - importing verified indicators into the local threat_intel table
  - rejecting tampered packages without importing anything

Both the CLI scripts (create_update.py / verify_update.py) and the
Flask blueprint (updates_api.py) call into this file, so there is only
one place where the actual verification logic lives.

Nothing in this file ever makes a network call. That is the point.
"""

import hashlib
import json
import os
import shutil
import sqlite3
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Paths (relative to this file, so it works no matter where you run it from)
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INCOMING_DIR = os.path.join(BASE_DIR, "incoming")
VERIFIED_DIR = os.path.join(BASE_DIR, "verified")
REJECTED_DIR = os.path.join(BASE_DIR, "rejected")

# Point this at the SAME sqlite file Member 1's backend uses, once you
# confirm the path with them. For standalone demo/testing it defaults to
# a local file sitting next to this folder.
DEFAULT_DB_PATH = os.environ.get(
    "AIRGAP_DB_PATH",
    os.path.join(BASE_DIR, "..", "airgap_sentinel.db"),
)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Create the threat_intel table if it doesn't already exist.

    Field names match what's agreed with Member 2:
        indicator, indicator_type, confidence, source, imported_at
    """
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_intel (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                confidence INTEGER,
                source TEXT,
                imported_at TEXT NOT NULL,
                update_version TEXT,
                UNIQUE(indicator, source, update_version)
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def import_indicators(indicators, update_version: str, db_path: str = DEFAULT_DB_PATH) -> int:
    """Insert indicators into threat_intel. Returns number of rows inserted.

    Uses INSERT OR IGNORE + a UNIQUE constraint so re-running verification
    on an already-imported package is harmless (no duplicate rows).
    """
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    inserted = 0
    try:
        now = datetime.now(timezone.utc).isoformat()
        for ind in indicators:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO threat_intel
                    (indicator, indicator_type, confidence, source, imported_at, update_version)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    ind.get("indicator"),
                    ind.get("indicator_type"),
                    ind.get("confidence"),
                    ind.get("source"),
                    now,
                    update_version,
                ),
            )
            inserted += cur.rowcount
        conn.commit()
    finally:
        conn.close()
    return inserted


def list_indicators(db_path: str = DEFAULT_DB_PATH):
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT indicator, indicator_type, confidence, source, imported_at, update_version "
            "FROM threat_intel ORDER BY imported_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------
def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Package creation  (this simulates what the "update machine" does OUTSIDE
# the air gap: build the package, hash it, seal the hash in a manifest)
# ---------------------------------------------------------------------------
def create_package(indicators=None, version=None, incoming_dir: str = INCOMING_DIR):
    """Write a new update package + its manifest into updates/incoming/.

    Returns (package_path, manifest_path, version).
    """
    os.makedirs(incoming_dir, exist_ok=True)

    if version is None:
        version = datetime.now().strftime("%Y.%m.%d-%H%M%S")

    if indicators is None:
        # Default demo indicator agreed with Member 2 for the detection rule
        indicators = [
            {
                "indicator": "10.0.0.99",
                "indicator_type": "ipv4",
                "confidence": 95,
                "source": "offline-threat-feed",
            }
        ]

    package = {"version": version, "indicators": indicators}

    package_filename = f"update-{version}.json"
    package_path = os.path.join(incoming_dir, package_filename)

    # Write with a fixed, deterministic format so the hash is stable/reproducible
    with open(package_path, "w", encoding="utf-8") as f:
        json.dump(package, f, indent=2, sort_keys=True)
        f.write("\n")

    expected_hash = sha256_of_file(package_path)

    manifest = {
        "package_file": package_filename,
        "version": version,
        "expected_sha256": expected_hash,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    manifest_filename = f"update-{version}.manifest.json"
    manifest_path = os.path.join(incoming_dir, manifest_filename)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    return package_path, manifest_path, version


# ---------------------------------------------------------------------------
# Verification + import  (this simulates what happens INSIDE the air gap
# when the sealed media is read: verify hash, import only if it matches)
# ---------------------------------------------------------------------------
def verify_and_import_all(
    incoming_dir: str = INCOMING_DIR,
    verified_dir: str = VERIFIED_DIR,
    rejected_dir: str = REJECTED_DIR,
    db_path: str = DEFAULT_DB_PATH,
):
    """Scan updates/incoming/ for manifest+package pairs, verify each one,
    import indicators for valid packages, and move each package out of
    incoming/ into verified/ or rejected/ accordingly.

    Returns a list of result dicts, one per package processed.
    """
    os.makedirs(verified_dir, exist_ok=True)
    os.makedirs(rejected_dir, exist_ok=True)

    results = []

    if not os.path.isdir(incoming_dir):
        return results

    manifest_files = sorted(
        f for f in os.listdir(incoming_dir) if f.endswith(".manifest.json")
    )

    for manifest_name in manifest_files:
        manifest_path = os.path.join(incoming_dir, manifest_name)

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        package_filename = manifest.get("package_file")
        expected_hash = manifest.get("expected_sha256")
        version = manifest.get("version")
        package_path = os.path.join(incoming_dir, package_filename) if package_filename else None

        result = {
            "manifest": manifest_name,
            "package_file": package_filename,
            "version": version,
        }

        if not package_path or not os.path.isfile(package_path):
            result["status"] = "REJECTED"
            result["reason"] = "PACKAGE FILE MISSING"
            results.append(result)
            continue

        actual_hash = sha256_of_file(package_path)
        result["expected_sha256"] = expected_hash
        result["actual_sha256"] = actual_hash

        if actual_hash != expected_hash:
            # --- HASH MISMATCH: reject, import nothing ---
            result["status"] = "REJECTED"
            result["reason"] = "HASH MISMATCH"
            _move_pair(package_path, manifest_path, rejected_dir)
            results.append(result)
            continue

        # --- Hash matches: safe to import ---
        with open(package_path, "r", encoding="utf-8") as f:
            package = json.load(f)

        indicators = package.get("indicators", [])
        inserted = import_indicators(indicators, version, db_path=db_path)

        result["status"] = "VERIFIED"
        result["indicators_found"] = len(indicators)
        result["indicators_imported"] = inserted
        _move_pair(package_path, manifest_path, verified_dir)
        results.append(result)

    return results


def _move_pair(package_path, manifest_path, dest_dir):
    os.makedirs(dest_dir, exist_ok=True)
    shutil.move(package_path, os.path.join(dest_dir, os.path.basename(package_path)))
    shutil.move(manifest_path, os.path.join(dest_dir, os.path.basename(manifest_path)))
