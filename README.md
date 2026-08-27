# Hardened Offline Update Mechanism — Member 4

Simulates the controlled path threat intelligence takes into the isolated
network: build a package on the outside, hash it, carry it in on media
(here: `updates/incoming/`), verify the hash before trusting a single byte
of it, and only import if it's untouched.

## Files

```
updates/
├── incoming/            # "media was just plugged in" — new packages land here
├── verified/            # packages that passed verification get moved here
├── rejected/            # packages that failed verification get moved here
├── updates_core.py      # all real logic (create / hash / verify / import) lives here
├── create_update.py     # CLI: run OUTSIDE the air gap to build a package
├── verify_update.py     # CLI: run INSIDE the air gap to verify + import
├── updates_api.py       # Flask blueprint: POST /updates/import, GET /updates/list
└── README.md
```

## Package format

```json
{
  "version": "2026.08.26-01",
  "indicators": [
    {
      "indicator": "10.0.0.99",
      "indicator_type": "ipv4",
      "confidence": 95,
      "source": "offline-threat-feed"
    }
  ]
}
```

Every package is written alongside a manifest (`*.manifest.json`) containing
the package's SHA-256 at creation time. That hash is the only thing verify_update.py
trusts — it never trusts the package's contents until the hash matches.

## Workflow

1. **Create a package** (simulates the update machine, outside the air gap):
   ```bash
   cd updates
   python create_update.py
   ```
   This writes `update-<version>.json` and `update-<version>.manifest.json`
   into `updates/incoming/`.

2. **Verify + import** (simulates plugging the media into the isolated system):
   ```bash
   python verify_update.py
   ```
   - Hash matches → indicators are inserted into the `threat_intel` table,
     and the package is moved into `updates/verified/`.
   - Hash doesn't match → **nothing is imported**, and the package is moved
     into `updates/rejected/`.

3. **Via the backend / dashboard**, the same logic is available over HTTP:
   ```bash
   curl -X POST http://<backend-host>/updates/import
   curl http://<backend-host>/updates/list
   ```

## Tamper demonstration (finale)

1. Run `python create_update.py` — creates a valid package.
2. Open the resulting `update-*.json` in `updates/incoming/` and change one
   character (e.g. `10.0.0.99` → `10.0.0.98`). **Do not touch the manifest.**
3. Run `python verify_update.py` again.
4. Expected output:
   ```
   Status  : UPDATE REJECTED — HASH MISMATCH
     Nothing was imported from this package.
   ```

This is the strong, easy-to-narrate finale moment: "we changed one character,
and the system caught it and refused to import anything."

## Integration with Member 1 (backend)

Mount the blueprint into the existing Flask app:

```python
from updates.updates_api import updates_bp
app.register_blueprint(updates_bp)
```

That adds `POST /updates/import` and `GET /updates/list` to whatever app
already exists. If Member 1's app isn't Flask, or isn't ready yet, you can
demo this piece completely standalone:

```bash
python updates/updates_api.py
```
Runs on `http://127.0.0.1:5050` with the same two endpoints plus `/health`.

**Important:** point `AIRGAP_DB_PATH` (env var) at the *same* SQLite file
Member 1's backend uses, once confirmed, so indicators actually show up in
the shared system rather than a separate local database. Default (if unset)
is `airgap_sentinel.db` one directory above `updates/`.

```bash
export AIRGAP_DB_PATH=/path/to/shared/airgap_sentinel.db
```

## Integration with Member 2 (detection)

Agreed schema for the `threat_intel` table:

| field           | meaning                              |
|-----------------|---------------------------------------|
| indicator       | the IOC value, e.g. `10.0.0.99`       |
| indicator_type  | `ipv4`, `domain`, `hash`, etc.        |
| confidence      | 0–100                                 |
| source          | e.g. `offline-threat-feed`            |
| imported_at     | UTC timestamp, set automatically      |
| update_version  | which package this came from          |

Confirm with Member 2 that a log entry involving source/destination
`10.0.0.99` correctly triggers their threat-intelligence detection rule
after this import runs — that's the cross-module proof point for the demo.

## QA checklist (from the test plan)

- [ ] Valid update package imports successfully
- [ ] Tampered package is rejected, nothing imported
- [ ] Imported indicator (`10.0.0.99`) is visible via `GET /updates/list`
- [ ] Imported indicator triggers Member 2's threat-intel alert
- [ ] Whole flow works with Wi-Fi/internet disabled (no calls in this code
      ever touch the network — verify by disabling networking and re-running
      the full demo once before freeze)

## What this deliberately does NOT do

Per scope: no real OS patching, no real firewall changes, no live cloud
threat-intel calls, no ML, no auth beyond what's already on the backend.
This is a proof-of-concept of the *verification discipline*, not a
production update agent.
