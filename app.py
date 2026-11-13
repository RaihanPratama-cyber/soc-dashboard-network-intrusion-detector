"""
SOC Dashboard — Network Intrusion Detector (Flask app).

Pages: Overview (/), Alerts (/alerts), Logs (/logs).
API:   /health, /api/summary, /api/alerts, /api/logs, /api/check (POST).

/api/check accepts a JSON body with either:
    {"rows": [ {row}, ... ]}        — parsed log rows, or
    {"csv": "timestamp,src_mac,..."} — raw CSV text (same columns as
                                        data/sample_attacks.csv)

and returns the detector alerts for that sample. Nothing is stored.
"""

from __future__ import annotations

import csv
import io
import json
import os
from collections import Counter

from flask import Flask, jsonify, render_template, request

from detector import analyze, summarize

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "data", "sample_attacks.csv")

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
def load_sample_rows():
    """Load the bundled sample dataset (list of dict rows)."""
    with open(DATA_FILE, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _rows_from_request(payload):
    """Normalize a /api/check payload into a list of row dicts."""
    if not isinstance(payload, dict):
        raise ValueError("body harus berupa objek JSON")
    if "rows" in payload:
        rows = payload["rows"]
        if not isinstance(rows, list):
            raise ValueError("'rows' harus berupa array")
        return rows
    if "csv" in payload:
        text = payload["csv"]
        if not isinstance(text, str):
            raise ValueError("'csv' harus berupa string")
        reader = csv.DictReader(io.StringIO(text))
        if reader.fieldnames is None:
            raise ValueError("CSV kosong atau tanpa header")
        return list(reader)
    raise ValueError("body harus berisi 'rows' atau 'csv'")


def _analysis():
    rows = load_sample_rows()
    alerts = analyze(rows)
    return rows, alerts, summarize(rows, alerts)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@app.route("/")
def overview():
    rows, alerts, summary = _analysis()
    per_minute = Counter(r["timestamp"][:16] for r in rows)
    timeline = [{"minute": m, "packets": c}
                for m, c in sorted(per_minute.items())]
    return render_template("index.html", summary=summary, alerts=alerts,
                           timeline=timeline)


@app.route("/alerts")
def alerts_page():
    rows, alerts, summary = _analysis()
    return render_template("alerts.html", alerts=alerts, summary=summary)


@app.route("/logs")
def logs_page():
    rows, alerts, summary = _analysis()
    return render_template("logs.html", rows=rows, summary=summary)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "soc-dashboard"})


@app.route("/api/summary")
def api_summary():
    rows, alerts, summary = _analysis()
    return jsonify(summary)


@app.route("/api/alerts")
def api_alerts():
    rows, alerts, summary = _analysis()
    return jsonify({"alerts": alerts, "total": len(alerts)})


@app.route("/api/logs")
def api_logs():
    rows, alerts, summary = _analysis()
    return jsonify({"rows": rows, "total": len(rows)})


@app.route("/api/check", methods=["POST"])
def api_check():
    """Check a submitted log/pcap sample and return detector alerts."""
    try:
        payload = request.get_json(force=True, silent=False)
        rows = _rows_from_request(payload)
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        return jsonify({"error": "body JSON tidak valid"}), 400
    alerts = analyze(rows)
    return jsonify({
        "total_rows": len(rows),
        "total_alerts": len(alerts),
        "alerts": alerts,
        "summary": summarize(rows, alerts),
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=False)
