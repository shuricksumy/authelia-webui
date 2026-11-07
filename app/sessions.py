"""Open Authelia sessions kept in Redis: list them per user, sign a user out everywhere.

Authelia stores each session as one Redis key `authelia-session:<random id>`. The value is
AES-256-GCM encrypted with SHA-256(`session.secret`) (nonce first, no associated data) and holds a
MessagePack map whose `KV["UserSession"]` is the session as JSON. There is no index by user, so
finding a user's sessions means reading every session key and decrypting it here. Re-check this
format on every Authelia bump (`tests/integration/test_sessions_redis.py` runs it against the real
thing). Only the Redis provider is supported: memory sessions live inside Authelia's process.

Rules this module keeps, because it holds the key to everyone's sessions:
- It never forges or changes a session: it only scans, reads and deletes keys. The Redis user the
  configurator logs in with should be allowed nothing else (docs/sessions.md has the ACL).
- Of a decrypted session it keeps a handful of fields. A session can carry a pending TOTP secret or
  WebAuthn data; none of that is read into an object, logged or shown, and no key or blob is ever
  logged either (a key is a live session id).
- Anything unexpected (Redis down, wrong secret, a changed format) is "unavailable" or "unreadable",
  never a guess: only keys that were proven to belong to the user are deleted.
- Every read is bounded (keys, time), and slow Redis answers time out, so a page never hangs on it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import msgpack
import redis
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if TYPE_CHECKING:
    from collections.abc import Callable

    from app.settings import Settings

log = logging.getLogger("app.sessions")

PREFIX = "authelia-session:"
PROBE_KEY = PREFIX + "authelia-startup-probe"  # written and removed by Authelia at startup
NONCE_BYTES = 12  # AES-GCM, in front of the ciphertext
MAX_KEYS = 50_000  # session keys read per request
BUDGET_S = 3.0  # seconds spent reading per request
BATCH = 200  # GET + PTTL pairs per round trip
DELETE_BATCH = 100
CACHE_S = 5.0  # the Users page and the Overview share one read
SOCKET_TIMEOUT_S = 2.0
MAX_PLAINTEXT = 1 << 20  # a decrypted session is a few hundred bytes; refuse anything absurd


class SessionsUnavailable(Exception):
    """Redis cannot be used or the secret cannot be read; the message is safe to show."""


@dataclass(frozen=True)
class SessionInfo:
    key: str = field(repr=False)  # the live session id: never shown, never logged
    username: str
    second_factor: bool
    last_activity: datetime | None
    first_factor_at: datetime | None
    second_factor_at: datetime | None
    remember_me: bool
    expires_in: int | None  # seconds left on the key, when Redis reports one


@dataclass(frozen=True)
class Snapshot:
    sessions: tuple[SessionInfo, ...]
    unreadable: int  # keys that did not decrypt or parse: another secret, or another format
    truncated: bool  # stopped by the key or time budget: the list may be incomplete
    taken_at: datetime

    def for_user(self, username: str) -> list[SessionInfo]:
        wanted = username.casefold()
        return [s for s in self.sessions if s.username.casefold() == wanted]

    def counts(self) -> Counter[str]:
        """Sessions per user, keyed by the lower-cased username."""
        return Counter(s.username.casefold() for s in self.sessions)

    @property
    def looks_like_wrong_secret(self) -> bool:
        """Every session key failed to decrypt: almost always the wrong secret (or a new format)."""
        return self.unreadable > 0 and not self.sessions


@dataclass(frozen=True)
class RevokeResult:
    deleted: int
    kept: int  # the caller's own session, when it was asked to stay
    complete: bool  # False when the read was cut short: some sessions may be left
    unreadable: int


def _timestamp(value: Any) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    try:
        return datetime.fromtimestamp(value, UTC)
    except (OverflowError, OSError, ValueError):
        return None


class SessionStore:
    def __init__(
        self,
        client: Any,
        secret_file: Path,
        *,
        cookie_name: str = "authelia_session",
        max_keys: int = MAX_KEYS,
        budget_s: float = BUDGET_S,
        cache_s: float = CACHE_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self._secret_file = secret_file
        self._cookie_name = cookie_name
        self._max_keys = max_keys
        self._budget_s = budget_s
        self._cache_s = cache_s
        self._clock = clock
        self._lock = threading.Lock()
        self._cache: tuple[float, Snapshot] | None = None

    @classmethod
    def from_settings(cls, settings: Settings) -> SessionStore | None:
        """None unless the owner switched the feature on (Redis address and secret file)."""
        if settings.SESSIONS_REDIS_URL is None or settings.SESSIONS_SECRET_FILE is None:
            return None
        password = settings.SESSIONS_REDIS_PASSWORD
        client = redis.Redis.from_url(
            settings.SESSIONS_REDIS_URL,
            username=settings.SESSIONS_REDIS_USERNAME or None,
            password=password.get_secret_value() if password else None,
            socket_timeout=SOCKET_TIMEOUT_S,
            socket_connect_timeout=SOCKET_TIMEOUT_S,
            decode_responses=False,
            client_name="authelia-configurator",
        )
        return cls(client, settings.SESSIONS_SECRET_FILE, cookie_name=settings.SESSIONS_COOKIE_NAME)

    # ------------------------------------------------------------------ reading

    def snapshot(self, *, fresh: bool = False) -> Snapshot:
        """The open sessions now (cached for a few seconds unless `fresh`)."""
        with self._lock:
            if not fresh and self._cache and self._clock() - self._cache[0] < self._cache_s:
                return self._cache[1]
            snap = self._read()
            self._cache = (self._clock(), snap)
            return snap

    def _aes_key(self) -> bytes:
        try:
            secret = self._secret_file.read_bytes().rstrip(b"\r\n")
        except OSError:
            raise SessionsUnavailable("the session secret file cannot be read") from None
        if not secret:
            raise SessionsUnavailable("the session secret file is empty")
        return hashlib.sha256(secret).digest()

    def _decode(self, aes_key: bytes, blob: bytes) -> dict[str, Any] | None:
        """The UserSession as a dict; {} for a session with no user yet; None when unreadable."""
        try:
            plain = AESGCM(aes_key).decrypt(blob[:NONCE_BYTES], blob[NONCE_BYTES:], None)
            if len(plain) > MAX_PLAINTEXT:
                return None
            outer = msgpack.unpackb(
                plain, raw=True, strict_map_key=False, max_str_len=MAX_PLAINTEXT,
                max_bin_len=MAX_PLAINTEXT, max_map_len=64, max_array_len=64,
            )  # fmt: skip
            values = outer.get(b"KV") if isinstance(outer, dict) else None
            raw = values.get(b"UserSession") if isinstance(values, dict) else None
            if raw is None:
                return {}
            loaded = json.loads(raw)
        except (InvalidTag, ValueError, TypeError, msgpack.exceptions.UnpackException):
            return None
        return loaded if isinstance(loaded, dict) else None

    def _read(self) -> Snapshot:
        aes_key = self._aes_key()
        started = self._clock()
        sessions: list[SessionInfo] = []
        unreadable = 0
        truncated = False
        try:
            keys: list[bytes] = []
            for key in self._client.scan_iter(match=PREFIX + "*", count=500):
                if key == PROBE_KEY.encode():
                    continue
                keys.append(key)
                if len(keys) >= self._max_keys or self._clock() - started > self._budget_s:
                    truncated = True
                    break
            for start in range(0, len(keys), BATCH):
                if self._clock() - started > self._budget_s:
                    truncated = True
                    break
                batch = keys[start : start + BATCH]
                pipe = self._client.pipeline(transaction=False)
                for key in batch:
                    pipe.get(key)
                    pipe.pttl(key)
                results = pipe.execute()
                for key, blob, ttl in zip(batch, results[0::2], results[1::2], strict=True):
                    if not isinstance(blob, bytes):
                        continue  # expired or deleted between the scan and the read
                    data = self._decode(aes_key, blob)
                    if data is None:
                        unreadable += 1
                        continue
                    username = data.get("Username")
                    if not isinstance(username, str) or not username:
                        continue  # a session nobody has signed in to
                    second = _timestamp(data.get("SecondFactorAuthnTimestamp"))
                    sessions.append(
                        SessionInfo(
                            key=key.decode("utf-8", "replace"),
                            username=username,
                            second_factor=second is not None,
                            last_activity=_timestamp(data.get("LastActivity")),
                            first_factor_at=_timestamp(data.get("FirstFactorAuthnTimestamp")),
                            second_factor_at=second,
                            remember_me=data.get("KeepMeLoggedIn") is True,
                            expires_in=ttl // 1000 if isinstance(ttl, int) and ttl >= 0 else None,
                        )
                    )
        except redis.exceptions.RedisError as err:
            raise self._unavailable(err) from None
        sessions.sort(
            key=lambda s: (s.username.casefold(), -(s.last_activity or _EPOCH).timestamp())
        )
        return Snapshot(tuple(sessions), unreadable, truncated, datetime.now(UTC))

    # ------------------------------------------------------------------ changing

    def revoke(self, username: str, keep: str | None = None) -> RevokeResult:
        """Delete every session of `username` (case-insensitive), except the key `keep`.

        Only keys that were just read and proven to hold this user are deleted.
        """
        if not username.strip():
            raise ValueError("a username is required")
        snap = self.snapshot(fresh=True)
        mine = snap.for_user(username)
        targets = [s.key for s in mine if s.key != keep]
        deleted = 0
        try:
            for start in range(0, len(targets), DELETE_BATCH):
                chunk = [k.encode("utf-8") for k in targets[start : start + DELETE_BATCH]]
                deleted += int(self._client.delete(*chunk))
        except redis.exceptions.RedisError as err:
            raise self._unavailable(err) from None
        with self._lock:
            self._cache = None  # the counts just changed
        return RevokeResult(deleted, len(mine) - len(targets), not snap.truncated, snap.unreadable)

    def current_key(self, cookie_header: str | None) -> str | None:
        """The Redis key of the session named in a request's Cookie header (its value is the id)."""
        for part in (cookie_header or "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == self._cookie_name and value:
                return PREFIX + value
        return None

    # ------------------------------------------------------------------ errors

    @staticmethod
    def _unavailable(err: redis.exceptions.RedisError) -> SessionsUnavailable:
        """A message that is safe to show; the details stay out (they can name hosts and users)."""
        log.warning("sessions unavailable: %s", type(err).__name__)
        if isinstance(err, redis.exceptions.AuthenticationError):
            return SessionsUnavailable("Redis refused the configurator's login")
        if isinstance(err, redis.exceptions.NoPermissionError):
            return SessionsUnavailable("the Redis user may not read or delete the session keys")
        if isinstance(err, (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError)):
            return SessionsUnavailable("Redis cannot be reached")
        return SessionsUnavailable("Redis returned an error")


_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
