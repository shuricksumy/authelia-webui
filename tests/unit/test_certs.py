"""Certificate expiry: chains, a live TLS handshake, thresholds and one-time notifications."""

from __future__ import annotations

import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app import certs
from app.apply import notify
from app.apply import state as apply_state
from app.oidc.jwks import entry_lines, key_path, new_document
from app.settings import Settings

NOW = datetime(2030, 6, 1, tzinfo=UTC)


def make_cert(days: float, cn: str = "unit.example.test") -> tuple[x509.Certificate, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=400))
        .not_valid_after(NOW + timedelta(days=days))
        .sign(key, hashes.SHA256())
    )  # fmt: skip
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return cert, pem


def settings(tmp_path: Path, **extra: object) -> Settings:
    managed = tmp_path / "managed"
    managed.mkdir(exist_ok=True)
    return Settings(
        AUTH_DOMAIN="auth.example.com", CONFIGURATOR_DOMAIN="authcfg.example.com",
        ADMIN_GROUP="admin", ALLOWED_CLIENT_CIDRS="10.8.0.0/24",  # type: ignore[arg-type]
        TRUSTED_PROXY_CIDRS="172.20.0.0/16",  # type: ignore[arg-type]
        AUTHELIA_CONTAINER="authelia", AUTHELIA_HEALTH_URL="http://authelia:9091/api/health",
        APP_SECRET_KEY="k" * 40,  # type: ignore[arg-type]
        CONFIG_MANAGED_DIR=managed, CONFIG_MAIN=tmp_path / "configuration.yml", **extra,
    )  # fmt: skip


def test_chain_parsing_reports_the_leaf_and_survives_garbage() -> None:
    cert, _ = make_cert(30)
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    [info] = certs.parse_chain(pem, "OIDC key a")
    assert info.subject == "unit.example.test" and info.not_after == cert.not_valid_after_utc
    [bad] = certs.parse_chain("not a certificate", "OIDC key b")
    assert bad.not_after is None and "could not be read" in bad.error


def test_warning_window_and_wording() -> None:
    soon, far, gone = (certs.CertInfo(n, "s", NOW + timedelta(days=d)) for n, d in
                       (("soon", 5), ("far", 90), ("gone", -3)))  # fmt: skip
    unknown = certs.CertInfo("x", "", None, "no")
    found = certs.warnings([far, soon, gone, unknown], 21, NOW)
    assert [i.source for i in found] == ["gone", "soon"]
    assert certs.describe_days(-3) == "expired 3 days ago"
    assert (
        certs.describe_days(0) == "expires today" and certs.describe_days(1) == "expires in 1 day"
    )


def test_keys_file_chain_is_checked_and_no_private_key_is_read(tmp_path: Path) -> None:
    s = settings(tmp_path)
    cert, _ = make_cert(10)
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    doc = new_document([entry_lines("k1", "RS256", key_path(s.CONFIG_MANAGED_DIR, "k1"))])
    text = (
        doc.render().rstrip("\n")
        + "\n        certificate_chain: |\n"
        + "".join(f"          {ln}\n" for ln in pem.splitlines())
    )
    (s.CONFIG_MANAGED_DIR / "oidc_jwks.yml").write_text(text)
    [info] = certs.key_chains(s)
    assert info.source == "OIDC key k1"
    assert info.not_after == cert.not_valid_after_utc


def test_main_config_chain_before_the_move(tmp_path: Path) -> None:
    s = settings(tmp_path)
    cert, _ = make_cert(12)
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    body = "".join(f"          {ln}\n" for ln in pem.splitlines())
    s.CONFIG_MAIN.write_text(
        "identity_providers:\n  oidc:\n    jwks:\n      - key_id: 'm'\n        key: |\n"
        "          secret\n        certificate_chain: |\n" + body
    )
    [info] = certs.key_chains(s)
    assert info.source == "OIDC key m" and info.not_after == cert.not_valid_after_utc


def test_live_tls_handshake_reads_even_an_untrusted_certificate(tmp_path: Path) -> None:
    cert, key_pem = make_cert(9, cn="live.example.test")
    crt, key = tmp_path / "c.pem", tmp_path / "k.pem"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key.write_bytes(key_pem)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(crt, key)
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve() -> None:
        conn, _ = server.accept()
        try:
            with context.wrap_socket(conn, server_side=True):
                pass
        except (ssl.SSLError, OSError):
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    info = certs.fetch_tls(f"127.0.0.1:{port}")
    thread.join(5)
    server.close()
    assert info.subject == "live.example.test" and info.not_after == cert.not_valid_after_utc
    down = certs.fetch_tls(f"127.0.0.1:{port}", timeout_s=1)  # nothing listens any more
    assert down.not_after is None and "could not connect" in down.error


def test_hosts_to_check(tmp_path: Path) -> None:
    assert certs.hosts_to_check(settings(tmp_path)) == ["auth.example.com", "authcfg.example.com"]
    assert certs.hosts_to_check(settings(tmp_path, CERT_CHECK_HOSTS="")) == []
    assert certs.hosts_to_check(settings(tmp_path, CERT_CHECK_HOSTS="a:8443, b")) == ["a:8443", "b"]


def test_one_notification_per_certificate_and_threshold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = settings(tmp_path)
    sent: list[str] = []
    monkeypatch.setattr(
        notify, "send", lambda settings, ev, res, user, msg, commit="": sent.append(msg)
    )
    expiry = NOW + timedelta(days=20)
    info = certs.CertInfo("TLS a:443", "a", expiry)

    def at(days_left: int) -> datetime:
        return expiry - timedelta(days=days_left)

    certs.notify_once(s, [info], at(30))
    assert sent == []  # outside the window
    certs.notify_once(s, [info], at(20))
    certs.notify_once(s, [info], at(19))  # same band: not again
    assert len(sent) == 1 and "expires in 20 days" in sent[0]
    certs.notify_once(s, [info], at(6))  # closer band: one more
    certs.notify_once(s, [info], at(5))
    assert len(sent) == 2
    # state survives a restart (it is on disk)
    assert apply_state.load(s.CONFIG_MANAGED_DIR)["cert_notified"]
    certs.notify_once(s, [info], at(5))
    assert len(sent) == 2
    renewed = certs.CertInfo("TLS a:443", "a", NOW + timedelta(days=400))
    certs.notify_once(s, [renewed], NOW)  # a renewed certificate drops the old memory...
    later = certs.CertInfo("TLS a:443", "a", NOW + timedelta(days=15))
    certs.notify_once(s, [later], NOW)  # ...and the next expiry warns afresh
    assert len(sent) == 3


def test_watcher_caches_and_never_raises(tmp_path: Path) -> None:
    s = settings(tmp_path, CERT_CHECK_HOSTS="")
    calls = []

    def collector(_: Settings) -> list[certs.CertInfo]:
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("boom")
        return [certs.CertInfo("x", "s", datetime.now(UTC) + timedelta(days=2))]

    watcher = certs.CertWatcher(s, collector)
    assert watcher.report() == []
    watcher.refresh()
    assert len(watcher.expiring()) == 1
    watcher.refresh()  # the failing run keeps the last good report
    assert len(watcher.report()) == 1


def test_a_failed_first_check_is_retried_soon_not_in_six_hours(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps: list[float] = []

    class Stop(Exception):
        pass

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        if len(sleeps) >= 3:
            raise Stop

    monkeypatch.setattr(certs.time, "sleep", fake_sleep)
    s = settings(tmp_path, CERT_CHECK_HOSTS="traefik:8443")
    results = iter(
        [
            [certs.CertInfo("TLS traefik:8443", "", None, "could not connect")],
            [certs.CertInfo("TLS traefik:8443", "t", datetime.now(UTC) + timedelta(days=90))],
        ]
    )
    watcher = certs.CertWatcher(s, lambda _: next(results))
    with pytest.raises(Stop):
        watcher._loop()
    assert sleeps == [3, certs.RETRY_S, certs.REFRESH_S]
