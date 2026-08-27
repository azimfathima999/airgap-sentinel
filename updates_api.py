"""
updates_api.py
==============
Exposes the hardened update mechanism as HTTP endpoints so Member 1's
backend and Member 3's dashboard can trigger/read it.

Two ways to use this:

1) MOUNTED into Member 1's existing Flask app (preferred for the final demo):

    from updates.updates_api import updates_bp
    app.register_blueprint(updates_bp)

   That's it — this adds POST /updates/import and GET /updates/list to
   whatever app Member 1 already has running.

2) STANDALONE, if Member 1's backend isn't ready yet and you need to
   demo/test your piece independently:

    python updates/updates_api.py

   This runs its own tiny Flask server on port 5050 with the same
   endpoints, so you are never blocked on integration.

Endpoints
---------
POST /updates/import
    Scans updates/incoming/ for any package+manifest pairs, verifies
    each against its SHA-256, imports indicators from valid packages
    into threat_intel, and rejects (without importing) any tampered
    package. Returns a JSON summary.

GET /updates/list
    Returns everything currently in the threat_intel table, most
    recent first. This is what the dashboard should call to show
    imported indicators.
"""

from flask import Blueprint, jsonify

from updates_core import verify_and_import_all, list_indicators

updates_bp = Blueprint("updates", __name__)


@updates_bp.route("/updates/import", methods=["POST"])
def updates_import():
    results = verify_and_import_all()

    verified = [r for r in results if r["status"] == "VERIFIED"]
    rejected = [r for r in results if r["status"] == "REJECTED"]

    return jsonify(
        {
            "processed": len(results),
            "verified_count": len(verified),
            "rejected_count": len(rejected),
            "results": results,
        }
    )


@updates_bp.route("/updates/list", methods=["GET"])
def updates_list():
    return jsonify(list_indicators())


# ---------------------------------------------------------------------------
# Standalone runner, only used if you need to demo this piece by itself
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    from flask import Flask

    app = Flask(__name__)
    app.register_blueprint(updates_bp)

    @app.route("/health")
    def health():
        return jsonify({"status": "OK", "service": "updates"})

    print("Running updates API standalone on http://127.0.0.1:5050")
    print("  POST /updates/import")
    print("  GET  /updates/list")
    print("  GET  /health")
    app.run(host="127.0.0.1", port=5050, debug=True)
