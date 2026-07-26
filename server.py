#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
server.py
=========
Runs the SOC dashboard + its ingestion agent as ONE always-on Railway
service:

  - Serves SOC-Dashboard.html and alerts.json at the service's public URL,
    so the dashboard's built-in loadAlerts() can fetch alerts.json over
    plain HTTP (this is what actually solves the "file:// can't fetch a
    local JSON file" limitation from before).
  - Runs fetch_and_classify_alerts.py on a background timer, every
    INGEST_INTERVAL_HOURS (default 2), writing into a Railway Volume so
    the data survives restarts/redeploys.
  - Exposes POST /api/run-now so you (or a button in the dashboard) can
    trigger an ingestion run on demand instead of waiting for the timer.

Environment variables (set these in Railway's "Variables" tab):
  ANTHROPIC_API_KEY      required — your Anthropic API key
  DATA_DIR               where alerts.json / seen_ids.json / logs live.
                         Point this at your mounted Volume, e.g. /data
  INGEST_INTERVAL_HOURS  how often to check the feeds (default: 2)
  PORT                   set automatically by Railway — do not set manually
"""

import os
import threading
import time
from datetime import datetime, timezone

from flask import Flask, send_from_directory, jsonify

import fetch_and_classify_alerts as fac

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(BASE_DIR, "data"))
os.makedirs(DATA_DIR, exist_ok=True)

# Point the ingestion script at the persistent volume instead of the
# read-only app directory.
fac.ALERTS_FILE = os.path.join(DATA_DIR, "alerts.json")
fac.SEEN_FILE = os.path.join(DATA_DIR, "seen_ids.json")
fac.LOG_FILE = os.path.join(DATA_DIR, "ingest_log.jsonl")

INTERVAL_HOURS = float(os.environ.get("INGEST_INTERVAL_HOURS", "2"))

app = Flask(__name__, static_folder=None)

_state = {"last_run": None, "last_error": None, "running": False}
_lock = threading.Lock()


@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "SOC-Dashboard.html")


@app.route("/alerts.json")
def alerts_json():
    if os.path.exists(fac.ALERTS_FILE):
        return send_from_directory(DATA_DIR, "alerts.json")
    return jsonify([])


@app.route("/api/status")
def status():
    return jsonify({
        "last_run": _state["last_run"],
        "last_error": _state["last_error"],
        "running": _state["running"],
        "alerts_count": len(fac.load_json(fac.ALERTS_FILE, [])),
        "interval_hours": INTERVAL_HOURS,
    })


@app.route("/api/run-now", methods=["POST"])
def run_now():
    if _state["running"]:
        return jsonify({"status": "already_running"}), 409
    threading.Thread(target=_safe_run, daemon=True).start()
    return jsonify({"status": "started"})


def _safe_run():
    with _lock:
        _state["running"] = True
    try:
        fac.main()
        _state["last_error"] = None
    except Exception as e:
        import traceback
        traceback.print_exc()  # full traceback in Railway's Deploy Logs
        _state["last_error"] = str(e)
    _state["last_run"] = datetime.now(timezone.utc).isoformat()
    _state["running"] = False


def _scheduler_loop():
    # Run once shortly after startup, then on the configured interval.
    time.sleep(10)
    while True:
        _safe_run()
        time.sleep(max(INTERVAL_HOURS, 0.1) * 3600)


if __name__ == "__main__":
    threading.Thread(target=_scheduler_loop, daemon=True).start()
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
