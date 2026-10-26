"""Target application -- the deliberately simple "victim" site.

This is the app that later phases will attack and that System 1 (Detection)
will watch. It contains no security hardening on purpose: plaintext credential
comparison, no rate limiting, no lockout. That is the point.

The access log format is the contract Detection reads in Phase 1, so it is
defined here once and kept boring: one JSON object per line, newline
delimited, written to both stdout and a file.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask, g, jsonify, request

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

APP_ROOT = Path(__file__).resolve().parent
LOG_DIR = Path(os.environ.get("TARGET_APP_LOG_DIR", APP_ROOT / "logs"))
LOG_FILE = LOG_DIR / "access.log"

# Hard-coded demo users. Plaintext on purpose -- this app is the target.
USERS = {
    "alice": "wonderland",
    "bob": "builder123",
    "admin": "admin",
}

PROFILES = {
    "alice": {"username": "alice", "role": "analyst", "email": "alice@example.test"},
    "bob": {"username": "bob", "role": "engineer", "email": "bob@example.test"},
    "admin": {"username": "admin", "role": "administrator", "email": "admin@example.test"},
}

BOOT_TIME = time.time()

# --------------------------------------------------------------------------
# Access logging
# --------------------------------------------------------------------------


class JsonLineFormatter(logging.Formatter):
    """Emit the record's pre-built dict as one compact JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(record.msg, separators=(",", ":"))


def _build_access_logger() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("target_app.access")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if logger.handlers:  # avoid duplicate handlers under the reloader
        return logger

    formatter = JsonLineFormatter()

    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger


access_log = _build_access_logger()


def client_ip() -> str:
    """Best-effort source IP.

    Behind a cloud load balancer the real client is the first entry of
    X-Forwarded-For; fall back to the socket peer when running bare.
    """
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


# --------------------------------------------------------------------------
# App
# --------------------------------------------------------------------------

app = Flask(__name__)


@app.before_request
def _start_timer() -> None:
    g.request_start = time.perf_counter()
    g.request_id = uuid.uuid4().hex[:12]
    # Endpoint handlers set this when the notion of success is meaningful
    # (e.g. a login attempt). None means "not applicable".
    g.auth_outcome = None
    g.auth_username = None


@app.after_request
def _write_access_log(response):
    duration_ms = round((time.perf_counter() - getattr(g, "request_start", 0)) * 1000, 2)

    entry = {
        # ---- Phase 1 Detection reads these fields. Do not rename. ----
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": getattr(g, "request_id", None),
        "source_ip": client_ip(),
        "method": request.method,
        "endpoint": request.path,
        "status_code": response.status_code,
        "success": response.status_code < 400,
        "auth_outcome": getattr(g, "auth_outcome", None),
        "username": getattr(g, "auth_username", None),
        "user_agent": request.headers.get("User-Agent", ""),
        "duration_ms": duration_ms,
    }
    access_log.info(entry)
    response.headers["X-Request-Id"] = entry["request_id"] or ""
    return response


@app.post("/login")
def login():
    """Accept username/password from JSON or form body; return success/failure."""
    data = request.get_json(silent=True) or request.form or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    g.auth_username = username or None

    if not username or not password:
        g.auth_outcome = "missing_credentials"
        return jsonify({"success": False, "error": "username and password are required"}), 400

    if USERS.get(username) == password:
        g.auth_outcome = "success"
        # No real session/token in Phase 0 -- nothing downstream needs one yet.
        return jsonify({"success": True, "username": username, "message": "login successful"}), 200

    g.auth_outcome = "invalid_credentials"
    return jsonify({"success": False, "error": "invalid username or password"}), 401


@app.get("/status")
def status():
    """Liveness/health endpoint. Used by curl checks and the cloud health probe."""
    return jsonify(
        {
            "service": "crisis-target-app",
            "status": "ok",
            "uptime_seconds": round(time.time() - BOOT_TIME, 1),
            "time": datetime.now(timezone.utc).isoformat(),
        }
    ), 200


@app.get("/profile")
def profile():
    """Return a user profile. Unauthenticated by design -- an IDOR to find later."""
    username = (request.args.get("username") or "").strip()
    g.auth_username = username or None

    if not username:
        return jsonify({"error": "username query parameter is required"}), 400

    record = PROFILES.get(username)
    if record is None:
        return jsonify({"error": "no such user"}), 404
    return jsonify(record), 200


@app.get("/")
def index():
    return jsonify(
        {
            "service": "crisis-target-app",
            "endpoints": ["POST /login", "GET /status", "GET /profile?username=", "GET /"],
        }
    ), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    # host 0.0.0.0 so the container / cloud VM can route to it.
    app.run(host="0.0.0.0", port=port, debug=False)
