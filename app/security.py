"""Application-level access control (SPEC §8 layer 4) and CSRF.

Every request except /healthz must:
1. come from a client IP inside ALLOWED_CLIENT_CIDRS. The client IP is taken from
   X-Forwarded-For only when the TCP peer is a trusted proxy (TRUSTED_PROXY_CIDRS), using
   the rightmost address that is not itself a trusted proxy. Any malformed entry makes us
   fall back to the peer address (fail closed);
2. carry Remote-User / Remote-Groups from a trusted proxy (Authelia forwardAuth via
   Traefik), with ADMIN_GROUP among the groups. These headers are ignored from anyone else.

State-changing requests (anything but GET/HEAD/OPTIONS) also need a CSRF token: an HMAC
(itsdangerous, keyed by APP_SECRET_KEY) bound to the user, sent in the X-CSRF-Token header,
plus a same-origin check when the browser sends Origin. The app sets no cookies.

Uvicorn must run with --no-proxy-headers so the ASGI scope holds the real TCP peer.
"""

from __future__ import annotations

import ipaddress
import logging
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from itsdangerous import BadSignature, URLSafeTimedSerializer
from starlette.datastructures import Headers
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.settings import Network, Settings

log = logging.getLogger("app.security")

type IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

EXEMPT_PATHS = frozenset({"/healthz"})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
CSRF_HEADER = "x-csrf-token"
CSRF_MAX_AGE_S = 12 * 3600

SECURITY_HEADERS: list[tuple[bytes, bytes]] = [
    (
        b"content-security-policy",
        b"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        b"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; "
        b"object-src 'none'",
    ),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
]
# Pages and API answers are never cached; vendored static files may be (they are not secret).
NO_STORE = (b"cache-control", b"no-store")
STATIC_CACHE = (b"cache-control", b"private, max-age=3600")


@dataclass(frozen=True)
class Identity:
    username: str
    groups: tuple[str, ...]
    client_ip: IPAddress


def _norm(ip: IPAddress) -> IPAddress:
    """::ffff:10.0.0.1 -> 10.0.0.1 (dual-stack sockets present IPv4 peers this way)."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _in(ip: IPAddress, networks: Sequence[Network]) -> bool:
    ip = _norm(ip)
    return any(ip.version == net.version and ip in net for net in networks)


def resolve_client_ip(
    peer: str | None, forwarded_for: str | None, trusted: Sequence[Network]
) -> IPAddress | None:
    """Client IP per the rules in the module docstring; None if the peer is unparsable."""
    try:
        peer_ip = _norm(ipaddress.ip_address(peer or ""))
    except ValueError:
        return None
    if not forwarded_for or not _in(peer_ip, trusted):
        return peer_ip
    chain: list[IPAddress] = []
    for part in forwarded_for.split(","):
        try:
            chain.append(_norm(ipaddress.ip_address(part.strip())))
        except ValueError:
            return peer_ip  # malformed header from our own proxy: trust nothing in it
    for ip in reversed(chain):
        if not _in(ip, trusted):
            return ip
    return chain[0] if chain else peer_ip


class CSRF:
    def __init__(self, secret_key: str) -> None:
        self._serializer = URLSafeTimedSerializer(secret_key, salt="csrf-v1")

    def issue(self, username: str) -> str:
        return self._serializer.dumps({"u": username, "n": secrets.token_urlsafe(16)})

    def verify(self, token: str | None, username: str) -> bool:
        if not token:
            return False
        try:
            data = self._serializer.loads(token, max_age=CSRF_MAX_AGE_S)
        except BadSignature:
            return False
        return isinstance(data, dict) and data.get("u") == username


class SecurityMiddleware:
    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.settings = settings
        self.csrf = CSRF(settings.APP_SECRET_KEY.get_secret_value())

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        cache = STATIC_CACHE if scope["path"].startswith("/static/") else NO_STORE

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                message.setdefault("headers", [])
                message["headers"] = [*message["headers"], *SECURITY_HEADERS, cache]
            await send(message)

        if scope["path"] in EXEMPT_PATHS:
            await self.app(scope, receive, send_with_headers)
            return

        denial = self._check(scope)
        if isinstance(denial, str):
            client = scope.get("client") or ("?", 0)
            # %r: the path is attacker-controlled and may contain newlines (log injection)
            log.warning("denied %s %r from peer %s: %s", scope["method"], scope["path"],
                        client[0], denial)  # fmt: skip
            response = PlainTextResponse("Forbidden", status_code=403)
            await response(scope, receive, send_with_headers)
            return

        scope.setdefault("state", {})
        scope["state"]["identity"] = denial
        scope["state"]["csrf_token"] = self.csrf.issue(denial.username)
        await self.app(scope, receive, send_with_headers)

    def _check(self, scope: Scope) -> Identity | str:
        s = self.settings
        headers = Headers(scope=scope)
        client = scope.get("client")
        peer = client[0] if client else None
        client_ip = resolve_client_ip(peer, headers.get("x-forwarded-for"), s.TRUSTED_PROXY_CIDRS)
        if client_ip is None:
            return "unparsable peer address"
        if not _in(client_ip, s.ALLOWED_CLIENT_CIDRS):
            return f"client {client_ip} not in ALLOWED_CLIENT_CIDRS"

        peer_ip = ipaddress.ip_address(peer) if peer else None
        if peer_ip is None or not _in(peer_ip, s.TRUSTED_PROXY_CIDRS):
            return "identity headers from an untrusted peer are ignored; no identity"
        username = (headers.get("remote-user") or "").strip()
        groups = tuple(
            g.strip() for g in (headers.get("remote-groups") or "").split(",") if g.strip()
        )
        if not username:
            return "no Remote-User"
        if s.ADMIN_GROUP not in groups:
            return f"user {username!r} lacks the admin group"

        if scope["method"] not in SAFE_METHODS:
            if not self.csrf.verify(headers.get(CSRF_HEADER), username):
                return "missing or invalid CSRF token"
            if not _same_origin(headers, s.CONFIGURATOR_DOMAIN):
                return "cross-origin request"
        return Identity(username, groups, client_ip)


def _same_origin(headers: Headers, host: str) -> bool:
    origin = headers.get("origin")
    if origin is None:
        return headers.get("sec-fetch-site") in (None, "same-origin")
    return origin.lower() in {f"https://{host.lower()}", f"https://{host.lower()}:443"} or (
        origin.lower().startswith(f"https://{host.lower()}:")
    )


def identity_of(state: Any) -> Identity:
    identity = getattr(state, "identity", None)
    if not isinstance(identity, Identity):  # pragma: no cover - middleware guarantees it
        raise RuntimeError("request reached a handler without an identity")
    return identity
