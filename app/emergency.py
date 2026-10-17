"""Break-glass access for when Authelia itself is down (docs/emergency.md).

A second port (`EMERGENCY_PORT`) that the compose file publishes on the host's 127.0.0.1 only; the
admin reaches it through an SSH tunnel. It replaces Authelia's login with one password whose digest
is in the environment, checked by the bundled Authelia binary. Because it is the one way past
Authelia, everything around it is strict:

- only on that port (the middleware branches on the local port), and only for Host `localhost` /
  `127.0.0.1`, which refuses DNS rebinding and any proxy route to it;
- 5 wrong passwords lock the login for 15 minutes, counted globally and persisted (a restart does
  not reset it), attempts serialised so parallel guesses cannot exceed the limit;
- a signed `HttpOnly`, `SameSite=Strict` cookie, 30 minutes idle and 2 hours at most, the only
  cookie this app ever sets;
- every login, failure and lockout is audited, and successes and lockouts are notified.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from dataclasses import dataclass

from itsdangerous import BadSignature, URLSafeTimedSerializer

from app.apply import audit, notify
from app.apply import state as apply_state
from app.authelia_cli import AutheliaCLI, AutheliaCLIError
from app.settings import Settings

log = logging.getLogger("app.emergency")

COOKIE = "emergency_session"
USERNAME = "emergency"
IDLE_S = 30 * 60
ABSOLUTE_S = 2 * 3600
MAX_FAILS = 5
LOCK_S = 15 * 60


@dataclass(frozen=True)
class Attempt:
    result: str  # ok | wrong | locked | error
    locked_for_s: int = 0


class Emergency:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.port = settings.EMERGENCY_PORT
        self._serializer = URLSafeTimedSerializer(
            settings.APP_SECRET_KEY.get_secret_value(), salt="emergency-v1"
        )
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.port is not None and self.settings.EMERGENCY_PASSWORD_HASH is not None

    def allowed_hosts(self) -> frozenset[str]:
        return frozenset({f"localhost:{self.port}", f"127.0.0.1:{self.port}"})

    def allowed_origins(self) -> frozenset[str]:
        return frozenset(f"http://{h}" for h in self.allowed_hosts())

    # ------------------------------------------------------------------ the password

    def locked_for(self, now: float | None = None) -> int:
        until = float(apply_state.load(self.settings.CONFIG_MANAGED_DIR).get("emergency", {})
                      .get("locked_until", 0))  # fmt: skip
        return max(0, int(until - (now or time.time())))

    def attempt(self, password: str, client_ip: str, now: float | None = None) -> Attempt:
        """Check a password. Serialised: the lockout counter cannot be raced."""
        moment = now or time.time()
        managed = self.settings.CONFIG_MANAGED_DIR
        digest = self.settings.EMERGENCY_PASSWORD_HASH
        if digest is None:
            return Attempt("error")
        with self._lock:
            remaining = self.locked_for(moment)
            if remaining:
                self._audit(client_ip, "locked", "attempt while locked")
                return Attempt("locked", remaining)
            try:
                cli = AutheliaCLI.local(self.settings.AUTHELIA_BINARY)
                ok = cli.validate_password(password, digest.get_secret_value())
            except AutheliaCLIError:
                log.warning("the emergency password could not be checked")
                return Attempt("error")  # not a wrong guess: it does not count
            record = dict(apply_state.load(managed).get("emergency") or {})
            if ok:
                apply_state.update(managed, emergency={"fails": 0, "locked_until": 0})
                self._audit(client_ip, "success", "emergency login")
                notify.send(self.settings, "emergency login", "success", USERNAME,
                            f"Emergency login from {client_ip}.")  # fmt: skip
                return Attempt("ok")
            fails = int(record.get("fails", 0)) + 1
            if fails >= MAX_FAILS:
                apply_state.update(managed, emergency={"fails": 0, "locked_until": moment + LOCK_S})
                self._audit(client_ip, "locked", f"{MAX_FAILS} wrong passwords: locked")
                notify.send(self.settings, "emergency login", "locked", USERNAME,
                            f"{MAX_FAILS} wrong emergency passwords from {client_ip}; "
                            f"login locked for {LOCK_S // 60} minutes.")  # fmt: skip
                return Attempt("locked", LOCK_S)
            apply_state.update(managed, emergency={"fails": fails, "locked_until": 0})
            self._audit(client_ip, "failed", f"wrong password ({fails}/{MAX_FAILS})")
            return Attempt("wrong")

    def _audit(self, client_ip: str, result: str, summary: str) -> None:
        audit.append(self.settings.CONFIG_MANAGED_DIR, audit.AuditEntry(
            ts=audit.now(), user=USERNAME, client_ip=client_ip, action="emergency-login",
            result=result, commit="", summary=summary,
        ))  # fmt: skip

    # ------------------------------------------------------------------ the session cookie

    def issue(self, started: float | None = None) -> str:
        return self._serializer.dumps({"s": started if started is not None else time.time()})

    def read(self, value: str | None, now: float | None = None) -> float | None:
        """The session's start time when the cookie is valid, else None. The cookie is signed with
        a timestamp that is renewed on every response, so `max_age` is the idle limit."""
        if not value:
            return None
        try:
            data = self._serializer.loads(value, max_age=IDLE_S)
        except BadSignature:
            return None
        started = data.get("s") if isinstance(data, dict) else None
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
