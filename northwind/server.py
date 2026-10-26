"""Northwind Cloud -- the branded company site in front of the target app (Phase 6, Task 1).

The target app (target_app/app.py, :8080) is the deliberately insecure victim and its routes, status
codes and access.log format are the contract Detection depends on. This module gives it a face
WITHOUT touching it:

* the pages (landing, sign-in, account) and their CSS are served from here, so loading a page or an
  asset never writes a line to the app's access.log (which would add noise to Detection's counts);
* ``POST /login``, ``GET /status`` and ``GET /profile`` are transparent pass-throughs to the app at the
  same paths: same request, same status code, same body. The client's address (or an incoming
  ``X-Forwarded-For``, which is how the attack simulator injects its fake source IPs) and
  ``User-Agent`` are forwarded, so the app logs exactly what it would have logged for a direct hit.

"Northwind Cloud" is a made-up company. Plain HTML/CSS/JS, no build step, no framework.

    .venv-app\\Scripts\\python -m northwind.server        # http://127.0.0.1:8081
"""

from __future__ import annotations

import os
from pathlib import Path

import requests
from flask import Flask, Response, request, send_from_directory

HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"
UPSTREAM = os.environ.get("TARGET_APP_URL", "http://127.0.0.1:8080").rstrip("/")
PORT = int(os.environ.get("SITE_PORT", "8081"))
_TIMEOUT = 10

app = Flask(__name__, static_folder=str(STATIC), static_url_path="/static")


def _proxy(path: str) -> Response:
    """Forward the request unchanged and return the app's answer unchanged."""
    headers = {}
    ctype = request.headers.get("Content-Type")
    if ctype:
        headers["Content-Type"] = ctype
    headers["User-Agent"] = request.headers.get("User-Agent", "")
    # Preserve the source the app should see: an explicit X-Forwarded-For wins (the simulator sets it),
    # otherwise the real peer of this connection.
    headers["X-Forwarded-For"] = request.headers.get("X-Forwarded-For") or request.remote_addr or ""
    try:
        upstream = requests.request(
            request.method, f"{UPSTREAM}{path}", params=request.args, data=request.get_data(),
            headers=headers, timeout=_TIMEOUT, allow_redirects=False,
        )
    except requests.RequestException:
        return Response('{"error":"the service is temporarily unavailable"}', status=502,
                        mimetype="application/json")
    out = Response(upstream.content, status=upstream.status_code,
                   mimetype=upstream.headers.get("Content-Type", "application/json"))
    if "X-Request-Id" in upstream.headers:
        out.headers["X-Request-Id"] = upstream.headers["X-Request-Id"]
    return out


@app.post("/login")
def login():
    return _proxy("/login")


@app.get("/status")
def status():
    return _proxy("/status")


@app.get("/profile")
def profile():
    return _proxy("/profile")


@app.get("/")
def landing():
    return send_from_directory(STATIC, "index.html")


@app.get("/signin")
def signin():
    return send_from_directory(STATIC, "signin.html")


@app.get("/account")
def account():
    return send_from_directory(STATIC, "account.html")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, debug=False)
