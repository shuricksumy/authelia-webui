"""Break-glass access for when Authelia itself is down (docs/emergency.md).

A second port (`EMERGENCY_PORT`) that the compose file publishes on the host's 127.0.0.1 only; the
admin reaches it through an SSH tunnel. It replaces Authelia's login with one password whose digest
is in the environment, checked by the bundled Authelia binary. Because it is the one way past
Authelia, everything around it is strict:

- only on that port (the middleware branches on the local port), and only for the host names
  `localhost` / `127.0.0.1` / `[::1]`, which refuses DNS rebinding and any proxy route to it;
- wrong passwords lock **the address they came from** (5 per 15 minutes), so another container on
  the same Docker network cannot lock the owner out exactly when the door is needed; a global
  ceiling (20 per 15 minutes from all addresses together) still bounds guessing. Attempts are
  serialised, and the counters live in their own file (a restart does not reset them);
- a signed `HttpOnly`, `SameSite=Strict` cookie, 30 minutes idle and 2 hours at most, the only
  cookie this app ever sets. It is bound to the password digest (rotating the password ends every
  session) and to a generation counter that "Sign out" increments (ending every session at once);
- every login, failure and lockout is audited (attempts against an existing lock are not, so the
  audit log cannot be flooded), successes and lockouts are notified.
"""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any

from itsdangerous import BadSignature, URLSafeTimedSerializer

from app.apply import audit, notify
from app.authelia_cli import AutheliaCLI, AutheliaCLIError
from app.settings import Settings

log = logging.getLogger("app.emergency")

COOKIE = "emergency_session"
USERNAME = "emergency"
IDLE_S = 30 * 60
ABSOLUTE_S = 2 * 3600
MAX_FAILS = 5  # per address
GLOBAL_MAX_FAILS = 20  # all addresses together
LOCK_S = 15 * 60
MAX_TRACKED = 256  # addresses remembered at most (the oldest are forgotten first)
LOOPBACK_NAMES = frozenset({"localhost", "127.0.0.1", "[::1]"})


@dataclass(frozen=True)
class Attempt:
    result: str  # ok | wrong | locked | error
    locked_for_s: int = 0


class Emergency:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.port = settings.EMERGENCY_PORT
        digest = settings.EMERGENCY_PASSWORD_HASH
        # The digest takes part in the signing key: a new password makes every old cookie invalid.
        bound = (
            hashlib.sha256(digest.get_secret_value().encode()).hexdigest()[:16] if digest else ""
        )
        self._serializer = URLSafeTimedSerializer(
            settings.APP_SECRET_KEY.get_secret_value(), salt=f"emergency-v2:{bound}"
        )
        self._lock = threading.Lock()
        self._path = settings.CONFIG_MANAGED_DIR / ".apply" / "emergency.json"

    @property
    def enabled(self) -> bool:
        return self.port is not None and self.settings.EMERGENCY_PASSWORD_HASH is not None

    # ------------------------------------------------------------------ host and origin

    @staticmethod
    def host_allowed(host: str) -> bool:
        """`localhost`, `127.0.0.1` or `[::1]`, on any port: the tunnel's local port is the
        admin's choice. Only the name matters against DNS rebinding and proxy routes."""
        host = host.strip().lower()
        if host.startswith("["):
            name = host[: host.find("]") + 1] if "]" in host else host
            rest = host[len(name) :]
        else:
            name, _, port = host.partition(":")
            rest = f":{port}" if port else ""
        if rest and not (rest.startswith(":") and rest[1:].isdigit()):
            return False
        return name in LOOPBACK_NAMES

    # ------------------------------------------------------------------ state (own file)

    def _load(self) -> dict[str, Any]:
        try:
            data = json.loads(self._path.read_text())
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, data: dict[str, Any]) -> None:
        self._path.parent.mkdir(mode=0o700, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(data, handle)
        os.replace(tmp, self._path)

    def generation(self) -> int:
        value = self._load().get("generation", 0)
        return value if isinstance(value, int) else 0

    def end_all_sessions(self) -> None:
        with self._lock:
            data = self._load()
            data["generation"] = self.generation() + 1
            self._save(data)

    # ------------------------------------------------------------------ the password

    def locked_for(self, client_ip: str, now: float | None = None) -> int:
        moment = now or time.time()
        data = self._load()
        mine = (data.get("ips") or {}).get(client_ip) or {}
        until = max(float(mine.get("locked_until", 0)),
                    float((data.get("global") or {}).get("locked_until", 0)))  # fmt: skip
        return max(0, int(until - moment))

    def attempt(self, password: str, client_ip: str, now: float | None = None) -> Attempt:
        """Check a password. Serialised: the counters cannot be raced."""
        moment = now or time.time()
        digest = self.settings.EMERGENCY_PASSWORD_HASH
        if digest is None:
            return Attempt("error")
        with self._lock:
            remaining = self.locked_for(client_ip, moment)
            if remaining:
                return Attempt("locked", remaining)  # not audited: it would let anyone flood it
            try:
                cli = AutheliaCLI.local(self.settings.AUTHELIA_BINARY)
                ok = cli.validate_password(password, digest.get_secret_value())
            except AutheliaCLIError:
                log.warning("the emergency password could not be checked")
                return Attempt("error")  # not a wrong guess: it does not count
            data = self._load()
            ips: dict[str, Any] = dict(data.get("ips") or {})
            if ok:
                ips.pop(client_ip, None)
                self._save({**data, "ips": ips})
                self._audit(client_ip, "success", "emergency login")
                notify.send(self.settings, "emergency login", "success", USERNAME,
                            f"Emergency login from {client_ip}.")  # fmt: skip
                return Attempt("ok")
            mine = dict(ips.get(client_ip) or {})
            fails = int(mine.get("fails", 0)) + 1
            glob = dict(data.get("global") or {})
            if moment - float(glob.get("since", 0)) > LOCK_S:
                glob = {"since": moment, "fails": 0, "locked_until": 0}
            glob["fails"] = int(glob.get("fails", 0)) + 1
            locked = 0
            if fails >= MAX_FAILS:
                mine = {"fails": 0, "locked_until": moment + LOCK_S, "seen": moment}
                locked = LOCK_S
            else:
                mine = {"fails": fails, "locked_until": 0, "seen": moment}
            if glob["fails"] >= GLOBAL_MAX_FAILS:
                glob["locked_until"] = moment + LOCK_S
                locked = LOCK_S
            ips[client_ip] = mine
            if len(ips) > MAX_TRACKED:  # forget the addresses seen longest ago
                for old in sorted(ips, key=lambda k: float(ips[k].get("seen", 0)))[
                    : len(ips) - MAX_TRACKED
                ]:
                    ips.pop(old)
            self._save({**data, "ips": ips, "global": glob})
            if locked:
                self._audit(client_ip, "locked", "too many wrong passwords: locked")
                notify.send(self.settings, "emergency login", "locked", USERNAME,
                            f"Too many wrong emergency passwords (last from {client_ip}); "
                            f"login locked for {LOCK_S // 60} minutes.")  # fmt: skip
                return Attempt("locked", locked)
            self._audit(client_ip, "failed", f"wrong password ({fails}/{MAX_FAILS})")
            return Attempt("wrong")

    def _audit(self, client_ip: str, result: str, summary: str) -> None:
        with contextlib.suppress(OSError):  # a full disk must not stop the check itself
            audit.append(self.settings.CONFIG_MANAGED_DIR, audit.AuditEntry(
                ts=audit.now(), user=USERNAME, client_ip=client_ip, action="emergency-login",
                result=result, commit="", summary=summary,
            ))  # fmt: skip

    # ------------------------------------------------------------------ the session cookie

    def issue(self, started: float | None = None) -> str:
        return self._serializer.dumps({
            "s": started if started is not None else time.time(), "g": self.generation(),
        })  # fmt: skip

    def read(self, value: str | None, now: float | None = None) -> float | None:
        """The session's start time when the cookie is valid, else None. The cookie is signed with
        a timestamp that is renewed on every response, so `max_age` is the idle limit."""
        if not value:
            return None
        try:
            data = self._serializer.loads(value, max_age=IDLE_S)
        except BadSignature:
            return None
        if not isinstance(data, dict) or data.get("g") != self.generation():
            return None  # signed out (or from before a sign-out)
        started = data.get("s")
        if not isinstance(started, int | float):
            return None
        return float(started) if (now or time.time()) - started <= ABSOLUTE_S else None

    def cookie_header(self, started: float) -> bytes:
        remaining = max(1, min(IDLE_S, int(ABSOLUTE_S - (time.time() - started))))
        attributes = f"HttpOnly; SameSite=Strict; Path=/; Max-Age={remaining}"
        return f"{COOKIE}={self.issue(started)}; {attributes}".encode()

    @staticmethod
    def clear_cookie_header() -> bytes:
        return f"{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".encode()


def peer_ip(peer: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(peer or "")
    except ValueError:
        return None
