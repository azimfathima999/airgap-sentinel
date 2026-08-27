"""
create_update.py
=================
Simulates the "update machine" step: build a threat-intel package,
hash it, and seal the expected hash in a manifest.

In the real design, this step happens on a separate machine OUTSIDE
the air gap, and the resulting package + manifest get carried in on
write-once removable media. For this proof of concept, it just writes
both files into updates/incoming/, which is where verify_update.py
expects to find them.

Usage:
    python updates/create_update.py
    python updates/create_update.py --version 2026.08.26-01
"""

import argparse
import json

from updates_core import create_package


def main():
    parser = argparse.ArgumentParser(description="Create a new offline update package.")
    parser.add_argument("--version", default=None, help="Version string (default: auto timestamp)")
    parser.add_argument(
        "--indicators",
        default=None,
        help='JSON list of indicators, e.g. \'[{"indicator":"10.0.0.99","indicator_type":"ipv4","confidence":95,"source":"offline-threat-feed"}]\'',
    )
    args = parser.parse_args()

    indicators = json.loads(args.indicators) if args.indicators else None

    package_path, manifest_path, version = create_package(indicators=indicators, version=args.version)

    print("UPDATE PACKAGE CREATED")
    print(f"  version   : {version}")
    print(f"  package   : {package_path}")
    print(f"  manifest  : {manifest_path}")
    print()
    print("Next step: run verify_update.py to verify + import this package.")
    print()
    print("Tamper demo: open the package JSON, change one character (e.g.")
    print("10.0.0.99 -> 10.0.0.98) WITHOUT touching the manifest, save it,")
    print("then run verify_update.py again. It should be REJECTED.")


if __name__ == "__main__":
    main()
