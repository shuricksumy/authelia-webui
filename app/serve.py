"""Run the app on its normal port and, when configured, on the emergency port.

One uvicorn server, two listening sockets, one app: the locks, the job board and the apply flow
are shared. The app tells the two apart by the local port of each connection (app/security.py).
Proxy headers stay off, like the plain `uvicorn --no-proxy-headers` this replaces.
"""

from __future__ import annotations

import socket

import uvicorn

from app.main import create_app
from app.settings import APP_PORT, load_settings


def _listen(port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))  # noqa: S104  (the container's own interface; compose publishes it)
    sock.set_inheritable(True)
    return sock


def main() -> None:
    settings = load_settings()
    app = create_app(settings)
    config = uvicorn.Config(
        app, host="0.0.0.0", port=APP_PORT, server_header=False,  # noqa: S104
        proxy_headers=False, log_level="info",
    )  # fmt: skip
    ports = [APP_PORT] + ([settings.EMERGENCY_PORT] if settings.EMERGENCY_PORT else [])
    uvicorn.Server(config).run(sockets=[_listen(p) for p in ports])


if __name__ == "__main__":
    main()
