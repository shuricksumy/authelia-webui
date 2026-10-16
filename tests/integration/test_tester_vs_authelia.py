"""Differential test: our rule tester vs the real Authelia forward-auth endpoint.

Runs the realistic (split) config in the pinned Authelia container and, for a matrix of
URL x method x user, compares the outcome class:
  allow  - HTTP 200
  login  - HTTP 302/303/401 (anonymous needs to log in, or basic auth = 1FA on a 2FA rule)
  deny   - HTTP 403
Users authenticate with HTTP basic auth on the Authorization header, which Authelia treats
as one factor. If this test fails after an Authelia bump, app/rules/tester.py needs a port.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import secrets
import subprocess
from collections.abc import Iterator
from itertools import product
from pathlib import Path

import httpx
import pytest

from app.config_merge import merge_all
from app.rules.tester import MatchResult, RequestObject, RuleTester, Subject
from tests.fixtures.stack import STACK, prepare

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
AUTHZ = "http://127.0.0.1:19091/api/authz/forward-auth"

# Groups as in tests/fixtures/realistic/users.example.yml
USERS: dict[str, tuple[str, ...]] = {
    "": (),
    "alice": ("admin", "dev"),
    "bob": ("home",),
    "family": ("family",),
}

URLS = [
    "https://auth.example.test/.well-known/openid-configuration",
    "https://auth.example.test/api/oidc/authorize",
    "https://auth.example.test/settings",
    "https://home.example.test/api/states",
    "https://home.example.test/auth/token",
    "https://home.example.test/auth/token?x=1",  # anchored regex + query string
    "https://home.example.test/lovelace",
    "https://cloud.example.test/status.php",
    "https://cloud.example.test/status.php?format=json",
    "https://cloud.example.test/apps/files",
    "https://photos.example.test/api/server/ping",
    "https://photos.example.test/api/assets/1",
    "https://photos.example.test/photos",
    "https://notes.example.test/_session",
    "https://notes.example.test/_utils/",
    "https://hooks.example.test/webhook/abc",
    "https://hooks.example.test/admin",
    "https://garage.example.test/",
    "https://deep.sub.example.test/",
    "https://example.test/",  # apex: not matched by *.example.test
    "https://authcfg.example.test/",  # the configurator's protected rules (networks + subject)
    "https://authcfg.example.test/rules",
    "https://locked.example.test/",
]
# Allowed (RFC 1918, like the Docker NAT address) and outside the allowed networks.
CLIENT_IPS = ["10.8.0.5", "203.0.113.9"]
METHODS = ["GET", "POST"]


def _compose(*args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "-f", str(ROOT / "compose.test.yml"), *args],
        capture_output=True, text=True, check=False, env=env, cwd=ROOT,
    )  # fmt: skip


@pytest.fixture(scope="module")
def authelia(authelia_version: str, cli: object) -> Iterator[str]:
    prepare()
    env = {**os.environ, "AUTHELIA_VERSION": authelia_version,
           "TEST_APP_SECRET_KEY": secrets.token_urlsafe(48),
           "DEV_UID": str(os.getuid()), "DEV_GID": str(os.getgid())}  # fmt: skip
    up = _compose("up", "-d", "--wait", "--wait-timeout", "120", "authelia", env=env)
    try:
        assert up.returncode == 0, up.stderr[-2000:]
        credentials = STACK.parent / "credentials.json"
        yield json.loads(credentials.read_text())["password"]
    finally:
        _compose("down", "-v", env=env)


@pytest.fixture(scope="module")
def tester() -> RuleTester:
    from ruamel.yaml import YAML

    yaml = YAML(typ="safe", pure=True)
    files = [STACK / "configuration.yml", *sorted((STACK / "managed").glob("*.yml"))]
    return RuleTester(merge_all(yaml.load(f.read_text()) for f in files))


def expected_class(result: MatchResult, anonymous: bool) -> str:
    if result.policy == "bypass":
        return "allow"
    if result.policy == "deny":
        return "deny"
    if anonymous or result.policy == "two_factor":
        return "login"  # basic auth only ever reaches one factor
    return "allow"


def observed_class(status: int) -> str:
    # 303 is the redirect Authelia uses for non-GET methods.
    login = {302: "login", 303: "login", 401: "login"}
    return {200: "allow", 403: "deny", **login}.get(status, f"http-{status}")


def test_tester_agrees_with_real_authelia(authelia: str, tester: RuleTester) -> None:
    password = authelia
    disagreements = []
    with httpx.Client(timeout=10) as http:
        for url, method, (user, groups), client_ip in product(
            URLS, METHODS, USERS.items(), CLIENT_IPS
        ):
            obj = RequestObject.from_url(url, method)
            result = tester.evaluate(obj, Subject(user, groups, ipaddress.ip_address(client_ip)))
            assert not result.uncertain, (url, result.uncertain)
            parts = httpx.URL(url)
            headers = {
                "X-Forwarded-Method": method,
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": parts.host,
                "X-Forwarded-URI": parts.raw_path.decode(),
                "X-Forwarded-For": client_ip,
            }
            if user:
                token = base64.b64encode(f"{user}:{password}".encode()).decode()
                headers["Authorization"] = f"Basic {token}"
            status = http.get(AUTHZ, headers=headers).status_code
            want = expected_class(result, anonymous=not user)
            got = observed_class(status)
            if want != got:
                rule = "default" if result.rule_index is None else f"#{result.rule_index + 1}"
                disagreements.append(
                    f"{method} {url} user={user or 'anon'} ip={client_ip}: "
                    f"tester {want} ({rule} {result.policy}) vs authelia {got}"
                )
    assert not disagreements, "\n".join(disagreements)
