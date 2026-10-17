"""Build the compose test/dev stack's files (all under the gitignored generated/ dir).

Starts from the realistic config (tests/fixtures/realistic), splits it with our own migration
script (the layout the app manages in production), then adapts it for the stack:
  - domains example.com -> example.test, session cookie on example.test, portal on :8443;
  - the configurator's protected rules (admin 2FA on allowed networks + explicit deny);
  - a self-signed wildcard certificate made by the bundled authelia binary;
  - Traefik static/dynamic config: portal on `websecure` (:8443), the configurator only on the
    `internal` entrypoint (:8444), both behind Authelia forwardAuth;
  - alice's TOTP seeded with a known (test-only) secret so e2e/dev can log in.

    uv run python -m tests.fixtures.stack [--authelia docker:<version>|local]
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from app.rules.document import RulesDocument
from app.rules.form import RuleForm, apply_form
from scripts import migrate_jwks
from scripts.split_config import (
    ACCESS_CONTROL_NAME,
    OIDC_CLIENTS_NAME,
    check_structural_equality,
    split,
)
from tests.fixtures.generate import GENERATED, generate, make_cli

DOMAIN = "example.test"
AUTH_HOST = f"auth.{DOMAIN}"
CONFIGURATOR_HOST = f"authcfg.{DOMAIN}"
LOCKED_HOST = f"locked.{DOMAIN}"  # a second app instance that allows only 192.0.2.0/24
# Test-only: Authelia *bypasses* this host on purpose. It proves the proxy strips client-forged
# Remote-User/Remote-Groups headers when Authelia does not set them (SPEC §8).
FORGE_HOST = f"forge.{DOMAIN}"
PORTAL_PORT, INTERNAL_PORT = 8443, 8444
# Where connections from the host arrive from inside Docker (NAT/gateway): RFC 1918.
ALLOWED_NETWORKS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
TRAEFIK_IP = "172.29.250.10"
STACK = GENERATED / "stack"
USERS_NAME = "users.yml"
USERNAME = "alice"
# Test-only TOTP secret, computed so no secret-looking literal sits in the source.
TOTP_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
X_AUTHELIA_CONFIG = ",".join(
    [
        "/config/configuration.yml",
        f"/config/managed/{ACCESS_CONTROL_NAME}",
        f"/config/managed/{OIDC_CLIENTS_NAME}",
        "/config/managed/oidc_jwks.yml",  # the signing keys, moved out by scripts/migrate_jwks.py
    ]
)


# Seeded access tests (SPEC §16.2). Chosen so the changes the e2e/integration tests apply never
# alter their outcome; anonymous ones are probed against the real Authelia after each apply.
ACCESS_TESTS = f"""# Access tests: each request and the policy it must get.
- name: Photos server ping is public
  url: https://photos.{DOMAIN}/api/server/ping
  expect: bypass
- name: Home Assistant API is public
  url: https://home.{DOMAIN}/api/states
  expect: bypass
- name: Configurator is denied outside the allowed networks
  url: https://{CONFIGURATOR_HOST}/
  ip: 203.0.113.9
  expect: deny
- name: Admin reaches the configurator with 2FA
  url: https://{CONFIGURATOR_HOST}/
  user: alice
  groups: [admin]
  expect: two_factor
"""


def adapt_main(text: str) -> str:
    text = text.replace("example.com", DOMAIN)
    portal = f"authelia_url: 'https://{AUTH_HOST}'"
    text = text.replace(portal, f"authelia_url: 'https://{AUTH_HOST}:{PORTAL_PORT}'")
    text = text.replace("file_path: /config/authelia.log", "file_path: /config/logs/authelia.log")
    # Phase 3: the users file lives in the managed dir (the configurator writes it)
    return text.replace("path: /config/users.yml", f"path: /config/managed/{USERS_NAME}")


def adapt_access_control(text: str) -> str:
    text = text.replace("example.com", DOMAIN)
    doc = RulesDocument.parse(text)
    admin = RuleForm(
        domain=[CONFIGURATOR_HOST],
        networks=ALLOWED_NETWORKS,
        subject=[["group:admin"]],
        policy="two_factor",
        note="Authelia Configurator: admins on allowed networks only (protected)",
    )
    deny = RuleForm(domain=[CONFIGURATOR_HOST], policy="deny", note="Everyone else (protected)")
    locked = RuleForm(
        domain=[LOCKED_HOST],
        networks=ALLOWED_NETWORKS,
        subject=[["group:admin"]],
        policy="two_factor",
        note="Second instance that only trusts 192.0.2.0/24 (isolation test)",
    )
    forge = RuleForm(
        domain=[FORGE_HOST],
        policy="bypass",
        resources=["^/.*$"],
        note="TEST ONLY: proves the proxy drops forged identity headers (e2e)",
    )
    # After the two auth-portal rules, before everything else (and the *.domain catch-all).
    for offset, form in enumerate((admin, deny, locked, forge)):
        doc = doc.insert(2 + offset, apply_form(form), note=form.note)
    return doc.render()


def traefik_dynamic() -> str:
    def router(name: str, host: str, entrypoint: str, service: str, auth: bool) -> str:
        middlewares = "\n      middlewares: [authelia]" if auth else ""
        return f"""    {name}:
      rule: Host(`{host}`)
      entryPoints: [{entrypoint}]
      service: {service}{middlewares}
      tls: {{}}
"""

    return (
        "tls:\n  certificates:\n    - certFile: /certs/public.crt\n"
        "      keyFile: /certs/private.pem\n"
        "http:\n  routers:\n"
        + router("portal", AUTH_HOST, "websecure", "authelia", False)
        + router("configurator", CONFIGURATOR_HOST, "internal", "configurator", True)
        + router("locked", LOCKED_HOST, "internal", "locked", True)
        + router("forge", FORGE_HOST, "internal", "configurator", True)
        + """    broken:
      rule: Host(`authcfg.example.test`) && Header(`X-Test-Instance`, `broken`)
      priority: 1000
      entryPoints: [internal]
      service: broken
      middlewares: [authelia]
      tls: {}
"""
        + """  middlewares:
    authelia:
      forwardAuth:
        address: http://authelia:9091/api/authz/forward-auth
        trustForwardHeader: true
        authResponseHeaders: [Remote-User, Remote-Groups, Remote-Email, Remote-Name]
  services:
    authelia: {loadBalancer: {servers: [{url: "http://authelia:9091"}]}}
    configurator: {loadBalancer: {servers: [{url: "http://configurator:8080"}]}}
    locked: {loadBalancer: {servers: [{url: "http://configurator-locked:8080"}]}}
    broken: {loadBalancer: {servers: [{url: "http://configurator-broken:8080"}]}}
"""
    )


def seed_totp(authelia_version: str) -> None:
    """Initialise Authelia's database and register a known TOTP secret for alice."""
    base = ["docker", "run", "--rm", "--network", "none", "-v", f"{STACK}:/config",
            "--user", f"{os.getuid()}:{os.getgid()}", "--entrypoint", "",
            f"authelia/authelia:{authelia_version}", "authelia", "storage"]  # fmt: skip
    config = [arg for path in X_AUTHELIA_CONFIG.split(",") for arg in ("--config", path)]
    config += ["--config.experimental.filters", "template"]
    for args in (
        ["migrate", "up"],
        ["user", "totp", "generate", USERNAME, "--secret", TOTP_SECRET, "--force"],
    ):
        proc = subprocess.run([*base, *args, *config], capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise RuntimeError(f"authelia storage {' '.join(args[:3])} failed")


def prepare(authelia: str = "auto") -> Path:
    cli = make_cli(authelia)
    files = generate(cli)
    original = files["configuration.yml"].read_text()
    result = split(original)
    check_structural_equality(original, result)
    managed = STACK / "managed"
    managed.mkdir(parents=True)
    main_text = adapt_main(result.main_text)
    # Phase 4c: like a real deployment after the one-time move, the signing keys are files in
    # managed/secrets/ named by managed/oidc_jwks.yml (Authelia reads them via the template filter)
    migration = migrate_jwks.plan(main_text, Path("/config/managed"))
    (STACK / "configuration.yml").write_text(migrate_jwks.without_jwks(main_text))
    (managed / ACCESS_CONTROL_NAME).write_text(adapt_access_control(result.access_control_text))
    if result.oidc_clients_text is None:
        raise RuntimeError("fixture has no OIDC clients")
    (managed / OIDC_CLIENTS_NAME).write_text(
        result.oidc_clients_text.replace("example.com", DOMAIN)
    )
    shutil.copy(files["users.yml"], managed / USERS_NAME)
    (managed / "access_tests.yml").write_text(ACCESS_TESTS)
    migrate_jwks.write(migration, managed)

    (STACK / "logs").mkdir()  # Authelia's log, shown read-only by the configurator
    certs = STACK / "certs"
    cli.rsa_certificate(certs, f"*.{DOMAIN}", sans=(f"*.{DOMAIN}", DOMAIN))
    traefik = STACK / "traefik"
    traefik.mkdir()
    (traefik / "dynamic.yml").write_text(traefik_dynamic())
    for path in (STACK, managed, certs, traefik, STACK / "logs"):
        path.chmod(0o755)  # containers run as the caller's uid, but Traefik runs as root
    for key in certs.iterdir():
        key.chmod(0o644)  # test-only wildcard cert for example.test

    version = re.search(r"authelia/authelia:(\S+)", " ".join(cli.argv_prefix))
    seed_totp(version.group(1) if version else _pinned_version())
    credentials = json.loads(files["credentials.json"].read_text())
    (STACK.parent / "credentials.json").write_text(
        json.dumps({**credentials, "username": USERNAME, "totp_secret": TOTP_SECRET}) + "\n"
    )
    (STACK.parent / "credentials.json").chmod(0o600)
    return STACK


def _pinned_version() -> str:
    from scripts.split_config import _dockerfile_version

    return _dockerfile_version()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--authelia", default="auto")
    print("stack ready:", prepare(parser.parse_args().authelia))
