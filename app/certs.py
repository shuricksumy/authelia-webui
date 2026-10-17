"""Certificate expiry: the OIDC key certificate chains and the live TLS certificates.

Only public data is read: the `certificate_chain` PEMs of the signing keys (never a private key)
and what a TLS handshake presents. A handshake here never validates the chain (an expired or
self-signed certificate is exactly what we want to report), it only reads it.

Warnings use `CERT_WARN_DAYS`; one notification is sent per certificate and threshold (state.json)
so a certificate that stays close to expiry does not nag every few hours.
"""

from __future__ import annotations

import logging
import socket
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from app.apply import notify
from app.apply import state as apply_state
from app.blocklist import DocumentError
from app.oidc.jwks import JWKS_NAME, JwksDocument
from app.settings import Settings

log = logging.getLogger("app.certs")
HANDSHAKE_TIMEOUT_S = 4.0
REFRESH_S = 6 * 3600
RETRY_S = 5 * 60  # when a check could not be completed (e.g. a host was not up yet)
THRESHOLDS = (0, 7, 21)  # days; the configured CERT_WARN_DAYS is added


@dataclass(frozen=True)
class CertInfo:
    source: str  # "OIDC key abc" / "TLS auth.example.com:443"
    subject: str
    not_after: datetime | None  # None: could not be determined
    error: str = ""  # plain-language reason when not_after is None

    def days_left(self, now: datetime | None = None) -> int | None:
        if self.not_after is None:
            return None
        return (self.not_after - (now or datetime.now(UTC))).days

    @property
    def id(self) -> str:
        return (
            f"{self.source}|{self.subject}|{self.not_after.isoformat() if self.not_after else ''}"
        )


def _describe(cert: x509.Certificate, source: str) -> CertInfo:
    names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    subject = str(names[0].value) if names else cert.subject.rfc4514_string()[:80]
    return CertInfo(source, subject, cert.not_valid_after_utc)


def parse_chain(pem: str, source: str) -> list[CertInfo]:
    """The leaf (first) certificate of a PEM chain. Intermediates are the issuer's business."""
    try:
        certs = x509.load_pem_x509_certificates(pem.encode())
    except ValueError:
        return [CertInfo(source, "", None, "the certificate chain could not be read")]
    return [_describe(certs[0], source)] if certs else []


def fetch_tls(target: str, timeout_s: float = HANDSHAKE_TIMEOUT_S) -> CertInfo:
    """The certificate a server presents for `host[:port]` (443 by default), via SNI = host."""
    host, _, port = target.rpartition(":") if target.count(":") == 1 else (target, "", "")
    host = host or target
    number = int(port) if port.isdigit() else 443
    source = f"TLS {host}:{number}"
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # read, never trust: we only report on the certificate
    try:
        with (
            socket.create_connection((host, number), timeout=timeout_s) as raw,
            context.wrap_socket(raw, server_hostname=host) as tls,
        ):
            der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as exc:
        return CertInfo(source, "", None, f"could not connect ({type(exc).__name__})")
    if not der:
        return CertInfo(source, "", None, "the server presented no certificate")
    return _describe(x509.load_der_x509_certificate(der), source)


def hosts_to_check(settings: Settings) -> list[str]:
    raw = settings.CERT_CHECK_HOSTS
    if raw is None:
        return list(dict.fromkeys([settings.AUTH_DOMAIN, settings.CONFIGURATOR_DOMAIN]))
    return [h.strip() for h in raw.split(",") if h.strip()]


def key_chains(settings: Settings) -> list[CertInfo]:
    """Certificate chains of the OIDC signing keys: the managed keys file, or the main config
    (before the one-time move)."""
    out: list[CertInfo] = []
    managed = settings.CONFIG_MANAGED_DIR / JWKS_NAME
    try:
        doc = JwksDocument.parse(managed.read_text())
        for key in doc.entries():
            if key.chain:
                out += parse_chain(key.chain, f"OIDC key {key.kid}")
        return out
    except OSError:
        pass
    except DocumentError:
        return [CertInfo("OIDC keys file", "", None, "the keys file could not be read")]
    try:
        data = YAML(typ="safe", pure=True).load(settings.CONFIG_MAIN.read_text())
    except (OSError, YAMLError):
        return out
    oidc = ((data or {}).get("identity_providers") or {}).get("oidc") or {}
    for entry in oidc.get("jwks") or []:
        chain = entry.get("certificate_chain") if isinstance(entry, dict) else None
        if isinstance(chain, str) and chain.strip():
            out += parse_chain(chain, f"OIDC key {entry.get('key_id', '?')}")
    return out


def collect(settings: Settings, fetch: Callable[[str], CertInfo] = fetch_tls) -> list[CertInfo]:
    found = key_chains(settings)
    found += [fetch(host) for host in hosts_to_check(settings)]
    return found


def warnings(infos: list[CertInfo], warn_days: int, now: datetime | None = None) -> list[CertInfo]:
    """Certificates that expire within `warn_days` (or already did), soonest first."""
    soon = [i for i in infos if (d := i.days_left(now)) is not None and d <= warn_days]
    return sorted(soon, key=lambda i: i.not_after or datetime.max.replace(tzinfo=UTC))


def describe_days(days: int) -> str:
    if days < 0:
        return f"expired {-days} day{'s' if days != -1 else ''} ago"
    return "expires today" if days == 0 else f"expires in {days} day{'s' if days != 1 else ''}"


def notify_once(settings: Settings, infos: list[CertInfo], now: datetime | None = None) -> None:
    """One notification per certificate and threshold; remembered across restarts."""
    managed = settings.CONFIG_MANAGED_DIR
    limits = sorted({*THRESHOLDS, settings.CERT_WARN_DAYS})
    try:
        sent: dict[str, int] = dict(apply_state.load(managed).get("cert_notified") or {})
    except (OSError, ValueError, AttributeError):
        sent = {}
    changed = False
    for info in warnings(infos, settings.CERT_WARN_DAYS, now):
        days = info.days_left(now)
        if days is None:
            continue
        band = next(limit for limit in limits if days <= limit)
        if sent.get(info.id, 10**6) <= band:
            continue
        sent[info.id] = band
        changed = True
        notify.send(
            settings, "certificate", "expiring", "-",
            f"{info.source} ({info.subject or 'unknown subject'}) {describe_days(days)}.",
        )  # fmt: skip
    if changed:
        live = {i.id for i in infos}
        try:
            apply_state.update(managed, cert_notified={k: v for k, v in sent.items() if k in live})
        except OSError:
            log.warning("could not remember which certificate warnings were sent")


class CertWatcher:
    """Collects the report in a background thread so no page waits for a TLS handshake."""

    def __init__(
        self,
        settings: Settings,
        collector: Callable[[Settings], list[CertInfo]] = collect,
        refresh_s: float = REFRESH_S,
    ) -> None:
        self.settings = settings
        self._collector = collector
        self._refresh_s = refresh_s
        self._lock = threading.Lock()
        self._infos: list[CertInfo] = []
        self._at = 0.0
        self._started = False

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
        threading.Thread(target=self._loop, name="cert-watch", daemon=True).start()

    def _loop(self) -> None:
        time.sleep(3)  # let the app come up first
        while True:
            infos = self.refresh()
            failed = (not infos and bool(hosts_to_check(self.settings))) or any(
                i.not_after is None for i in infos
            )
            time.sleep(min(self._refresh_s, RETRY_S) if failed else self._refresh_s)

    def refresh(self) -> list[CertInfo]:
        try:
            infos = self._collector(self.settings)
            notify_once(self.settings, infos)
        except Exception:
            log.exception("certificate check failed")
            return self.report()
        with self._lock:
            self._infos, self._at = infos, time.monotonic()
        return infos

    def report(self) -> list[CertInfo]:
        with self._lock:
            return list(self._infos)

    def expiring(self) -> list[CertInfo]:
        return warnings(self.report(), self.settings.CERT_WARN_DAYS)
