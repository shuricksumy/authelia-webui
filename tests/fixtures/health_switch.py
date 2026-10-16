"""TEST ONLY health endpoint for the `configurator-broken` instance (compose.test.yml).

Answers 503 while the live access_control.yml contains the marker "break-health", otherwise relays
Authelia's own /api/health. So an apply that adds the marker is "unhealthy" and must be rolled
back, and after the rollback the system is healthy again - a real end-to-end rollback test.
"""

from __future__ import annotations

import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

LIVE = Path("/config/managed/access_control.yml")
AUTHELIA_HEALTH = "http://authelia:9091/api/health"
MARKER = "break-health"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        try:
            broken = MARKER in LIVE.read_text()
        except OSError:
            broken = True
        try:
            with urllib.request.urlopen(AUTHELIA_HEALTH, timeout=2) as response:
                healthy = response.status == 200
        except OSError:
            healthy = False
        self.send_response(200 if healthy and not broken else 503)
        self.end_headers()

    def log_message(self, *args: object) -> None:
        return


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()  # noqa: S104 - internal test network
