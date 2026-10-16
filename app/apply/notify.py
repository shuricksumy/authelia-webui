"""Optional webhook notifications (SPEC §16.5): apply, rollback, version mismatch.

A generic JSON POST. The payload never contains diffs, rule content or secrets - only a summary,
the author, the result and the commit id. `title`/`message`/`text` make one payload usable as-is
for Gotify, Home Assistant webhooks, Telegram sendMessage and ntfy templates (see README).
Sending happens in a background thread with a short timeout; failures are logged (without the
URL, which may hold a token) and never affect the apply.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

import httpx

from app.settings import Settings

log = logging.getLogger("app.notify")
TIMEOUT_S = 5.0


def payload(settings: Settings, event: str, result: str, user: str, summary: str,
            commit: str = "") -> dict[str, Any]:  # fmt: skip
    title = f"Authelia Configurator: {event} {result}".strip()
    message = summary if not commit else f"{summary} (commit {commit[:7]})"
    return {
        "title": title,
        "message": message,
        "text": f"{title}\n{message}",
        "event": event,
        "result": result,
        "user": user,
        "commit": commit[:12],
        "ts": int(time.time()),
        "host": settings.CONFIGURATOR_DOMAIN,
    }


def _post(url: str, body: dict[str, Any]) -> None:
    try:
        response = httpx.post(url, json=body, timeout=TIMEOUT_S)
        if response.status_code >= 400:
            log.warning("notification webhook answered HTTP %s", response.status_code)
    except httpx.HTTPError as exc:
        log.warning("notification webhook failed (%s)", type(exc).__name__)


def send(settings: Settings, event: str, result: str, user: str, summary: str,
         commit: str = "", wait: bool = False) -> bool:  # fmt: skip
    """Fire and forget. Returns False when no webhook is configured."""
    if settings.NOTIFY_WEBHOOK_URL is None:
        return False
    url = settings.NOTIFY_WEBHOOK_URL.get_secret_value()
    body = payload(settings, event, result, user, summary, commit)
    thread = threading.Thread(target=_post, args=(url, body), name="notify", daemon=True)
    thread.start()
    if wait:
        thread.join(TIMEOUT_S + 1)
    return True
