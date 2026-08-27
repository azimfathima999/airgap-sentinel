"""
verify_update.py
=================
Simulates the step that happens INSIDE the isolated network: read
whatever package(s) have been dropped into updates/incoming/ (the
stand-in for "sealed media was just plugged in"), verify each one's
SHA-256 against its manifest, and only import indicators for packages
that pass verification. Tampered packages are rejected and nothing
from them is imported.

Usage:
    python updates/verify_update.py
"""

from updates_core import verify_and_import_all


def main():
    results = verify_and_import_all()

    if not results:
        print("No update packages found in updates/incoming/.")
        print("Run create_update.py first.")
        return

    for r in results:
        print("-" * 60)
        print(f"Package : {r.get('package_file')}")
        print(f"Version : {r.get('version')}")

        if r["status"] == "VERIFIED":
            print("Status  : UPDATE VERIFIED")
            print(f"  expected sha256 : {r['expected_sha256']}")
            print(f"  actual   sha256 : {r['actual_sha256']}")
            print(f"  indicators found   : {r['indicators_found']}")
            print(f"  indicators imported: {r['indicators_imported']}")
        else:
            print("Status  : UPDATE REJECTED — " + r.get("reason", "UNKNOWN"))
            if "expected_sha256" in r:
                print(f"  expected sha256 : {r['expected_sha256']}")
                print(f"  actual   sha256 : {r['actual_sha256']}")
            print("  Nothing was imported from this package.")

    print("-" * 60)


if __name__ == "__main__":
    main()
