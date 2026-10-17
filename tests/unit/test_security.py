"""SPEC §8 layer 4: client IP, identity headers, CSRF. Proxy 172.20.0.2, VPN 10.8.0.0/24."""

from __future__ import annotations

import ipaddress

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app.main import create_app
from app.security import CSRF, identity_of, resolve_client_ip
from app.settings import Settings, parse_cidrs

TRUSTED = parse_cidrs("172.20.0.0/16")
PROXY = "172.20.0.2"
VPN_CLIENT = "10.8.0.5"
INTERNET = "203.0.113.50"
ADMIN = {"Remote-User": "alice", "Remote-Groups": "dev,admin"}


def settings() -> Settings:
    return Settings(
        AUTH_DOMAIN="auth.example.com",
        CONFIGURATOR_DOMAIN="authcfg.example.com",
        ADMIN_GROUP="admin",
        ALLOWED_CLIENT_CIDRS="10.8.0.0/24",  # type: ignore[arg-type]
        TRUSTED_PROXY_CIDRS="172.20.0.0/16",  # type: ignore[arg-type]
        AUTHELIA_CONTAINER="authelia",
        AUTHELIA_HEALTH_URL="http://authelia:9091/api/health",
        APP_SECRET_KEY="k" * 40,  # type: ignore[arg-type]
    )


def client(peer: str) -> TestClient:
    app = create_app(settings())

    @app.get("/whoami")
    def whoami(request: Request) -> dict[str, object]:
        ident = identity_of(request.state)
        return {
            "user": ident.username,
            "ip": str(ident.client_ip),
            "csrf": request.state.csrf_token,
        }

    @app.post("/mutate")
    def mutate() -> dict[str, bool]:
        return {"ok": True}

    return TestClient(app, client=(peer, 40000), base_url="https://authcfg.example.com")


# --------------------------------------------------------------------- client IP resolution


@pytest.mark.parametrize(
    ("peer", "xff", "expected"),
    [
        (PROXY, f"{VPN_CLIENT}", VPN_CLIENT),  # normal: proxy appends real client
        (PROXY, f"{VPN_CLIENT}, {INTERNET}", INTERNET),  # spoofed left part, real client right
        (PROXY, f"{INTERNET}, 172.20.0.9", INTERNET),  # skip trusted hops from the right
        (PROXY, None, PROXY),
        (PROXY, "not-an-ip", PROXY),  # malformed -> fall back to peer (fail closed)
        (INTERNET, VPN_CLIENT, INTERNET),  # untrusted peer cannot claim an XFF address
        (VPN_CLIENT, None, VPN_CLIENT),
    ],
)
def test_resolve_client_ip(peer: str, xff: str | None, expected: str) -> None:
    assert resolve_client_ip(peer, xff, TRUSTED) == ipaddress.ip_address(expected)


def test_unparsable_peer_is_none() -> None:
    assert resolve_client_ip("testclient", None, TRUSTED) is None


# --------------------------------------------------------------------- request matrix


def test_admin_via_trusted_proxy_from_vpn_is_allowed() -> None:
    r = client(PROXY).get("/whoami", headers={**ADMIN, "X-Forwarded-For": VPN_CLIENT})
    assert r.status_code == 200
    assert r.json()["user"] == "alice" and r.json()["ip"] == VPN_CLIENT


@pytest.mark.parametrize(
    ("peer", "headers"),
    [
        (PROXY, {**ADMIN, "X-Forwarded-For": INTERNET}),  # client outside allow-list
        (PROXY, {**ADMIN, "X-Forwarded-For": f"{VPN_CLIENT}, {INTERNET}"}),  # spoofed XFF
        (INTERNET, {**ADMIN, "X-Forwarded-For": VPN_CLIENT}),  # direct, spoofed XFF
        (VPN_CLIENT, ADMIN),  # allowed network but bypassing the proxy: headers forged
        (PROXY, {"X-Forwarded-For": VPN_CLIENT}),  # no identity
        (PROXY, {"X-Forwarded-For": VPN_CLIENT, "Remote-User": "bob", "Remote-Groups": "family"}),
        (PROXY, {"X-Forwarded-For": VPN_CLIENT, "Remote-User": "bob", "Remote-Groups": "admins"}),
        (PROXY, {"X-Forwarded-For": VPN_CLIENT, "Remote-User": "", "Remote-Groups": "admin"}),
    ],
)
def test_denied(peer: str, headers: dict[str, str]) -> None:
    r = client(peer).get("/whoami", headers=headers)
    assert r.status_code == 403
    assert "alice" not in r.text


def test_healthz_needs_no_identity_but_everything_else_does() -> None:
    c = client(INTERNET)
    assert c.get("/healthz").text == "ok"
    assert c.get("/version").status_code == 403


def test_security_headers_on_allowed_denied_and_exempt() -> None:
    c = client(PROXY)
    for r in (
        c.get("/whoami", headers={**ADMIN, "X-Forwarded-For": VPN_CLIENT}),
        c.get("/whoami"),
        c.get("/healthz"),
    ):
        csp = r.headers["content-security-policy"]
        assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
        assert "unsafe-inline" not in csp
        assert r.headers["x-content-type-options"] == "nosniff"
        assert "set-cookie" not in r.headers  # the app sets no cookies
        assert r.headers["cache-control"] == "no-store"


# --------------------------------------------------------------------- CSRF


def _token(c: TestClient) -> str:
    return str(c.get("/whoami", headers={**ADMIN, "X-Forwarded-For": VPN_CLIENT}).json()["csrf"])


def test_post_with_valid_token_and_same_origin() -> None:
    c = client(PROXY)
    headers = {**ADMIN, "X-Forwarded-For": VPN_CLIENT, "X-CSRF-Token": _token(c),
               "Origin": "https://authcfg.example.com"}  # fmt: skip
    assert c.post("/mutate", headers=headers).status_code == 200


@pytest.mark.parametrize(
    "change",
    [
        {"X-CSRF-Token": ""},
        {"X-CSRF-Token": "forged.token.value"},
        {"Origin": "https://evil.example.org"},
        {"Origin": "http://authcfg.example.com"},  # scheme downgrade
        {"Remote-User": "carol"},  # token bound to alice
    ],
)
def test_post_rejected(change: dict[str, str]) -> None:
    c = client(PROXY)
    headers = {**ADMIN, "X-Forwarded-For": VPN_CLIENT, "X-CSRF-Token": _token(c),
               "Origin": "https://authcfg.example.com", **change}  # fmt: skip
    assert c.post("/mutate", headers=headers).status_code == 403


def test_post_without_origin_requires_same_origin_fetch_metadata() -> None:
    c = client(PROXY)
    base = {**ADMIN, "X-Forwarded-For": VPN_CLIENT, "X-CSRF-Token": _token(c)}
    assert c.post("/mutate", headers={**base, "Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert c.post("/mutate", headers={**base, "Sec-Fetch-Site": "same-origin"}).status_code == 200


def test_csrf_token_from_another_key_is_rejected() -> None:
    other = CSRF("x" * 40).issue("alice")
    assert not CSRF("k" * 40).verify(other, "alice")
    assert CSRF("k" * 40).verify(CSRF("k" * 40).issue("alice"), "alice")


def test_ipv4_mapped_peers_are_normalised() -> None:
    """Dual-stack sockets present IPv4 peers as ::ffff:a.b.c.d; trust must still apply."""
    ip = resolve_client_ip(f"::ffff:{PROXY}", f"::ffff:{VPN_CLIENT}", TRUSTED)
    assert ip == ipaddress.ip_address(VPN_CLIENT)


def test_denial_log_cannot_be_forged_with_newlines(caplog: pytest.LogCaptureFixture) -> None:
    client(INTERNET).get("/x%0aINFO%20fake%20entry")
    record = next(r for r in caplog.records if r.name == "app.security")
    assert "\n" not in record.getMessage()


def test_a_refusal_shows_the_address_as_seen_but_not_the_reason() -> None:
    # through Traefik, from outside the allowed networks
    outside = client(PROXY).get("/whoami", headers={"X-Forwarded-For": INTERNET, **ADMIN})
    assert outside.status_code == 403
    assert f"Your address as seen here: {INTERNET}" in outside.text
    assert "ALLOWED_CLIENT_CIDRS" not in outside.text and "admin group" not in outside.text
    # not from Traefik: the forged header is ignored and the real peer is what is shown
    stranger = "192.0.2.77"
    direct = client(stranger).get("/whoami", headers={"X-Forwarded-For": VPN_CLIENT, **ADMIN})
    assert direct.status_code == 403
    assert f"seen here: {stranger}" in direct.text and VPN_CLIENT not in direct.text


def test_allow_any_client_network_still_needs_the_proxy_identity_and_group() -> None:
    def open_client(peer: str) -> TestClient:
        s = settings()
        s.ALLOW_ANY_CLIENT_NETWORK = True
        app = create_app(s)

        @app.get("/whoami")
        def whoami(request: Request) -> dict[str, object]:
            return {"user": identity_of(request.state).username}

        return TestClient(app, client=(peer, 5000), base_url="https://authcfg.example.com")

    via_proxy = open_client(PROXY)
    # any client address is accepted through the proxy, with Authelia's admin identity
    assert (
        via_proxy.get("/whoami", headers={"X-Forwarded-For": INTERNET, **ADMIN}).status_code == 200
    )
    # ...but never without the admin group or without an identity
    non_admin = {"Remote-User": "bob", "Remote-Groups": "family"}
    assert (
        via_proxy.get("/whoami", headers={"X-Forwarded-For": INTERNET, **non_admin}).status_code
        == 403
    )
    assert via_proxy.get("/whoami", headers={"X-Forwarded-For": INTERNET}).status_code == 403
    # and headers from anyone but the proxy are still ignored
    direct = open_client(INTERNET)
    assert direct.get("/whoami", headers=ADMIN).status_code == 403
