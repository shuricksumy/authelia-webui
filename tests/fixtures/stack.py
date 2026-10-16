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
PORTAL_PORT, INTERNAL_PORT = 8443, 8444
# Where connections from the host arrive from inside Docker (NAT/gateway): RFC 1918.
ALLOWED_NETWORKS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
TRAEFIK_IP = "172.29.250.10"
STACK = GENERATED / "stack"
USERNAME = "alice"
# Test-only TOTP secret, computed so no secret-looking literal sits in the source.
TOTP_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
X_AUTHELIA_CONFIG = ",".join(
    [
        "/config/configuration.yml",
        f"/config/managed/{ACCESS_CONTROL_NAME}",
        f"/config/managed/{OIDC_CLIENTS_NAME}",
    ]
)


def adapt_main(text: str) -> str:
    text = text.replace("example.com", DOMAIN)
    portal = f"authelia_url: 'https://{AUTH_HOST}'"
    return text.replace(portal, f"authelia_url: 'https://{AUTH_HOST}:{PORTAL_PORT}'")


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
    # After the two auth-portal rules, before everything else (and the *.domain catch-all).
    for offset, form in enumerate((admin, deny, locked)):
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
"""
    )


def seed_totp(authelia_version: str) -> None:
    """Initialise Authelia's database and register a known TOTP secret for alice."""
    base = ["docker", "run", "--rm", "--network", "none", "-v", f"{STACK}:/config",
            "--user", f"{os.getuid()}:{os.getgid()}", "--entrypoint", "",
            f"authelia/authelia:{authelia_version}", "authelia", "storage"]  # fmt: skip
    config = [arg for path in X_AUTHELIA_CONFIG.split(",") for arg in ("--config", path)]
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
    (STACK / "configuration.yml").write_text(adapt_main(result.main_text))
    (managed / ACCESS_CONTROL_NAME).write_text(adapt_access_control(result.access_control_text))
    if result.oidc_clients_text is None:
        raise RuntimeError("fixture has no OIDC clients")
    (managed / OIDC_CLIENTS_NAME).write_text(
        result.oidc_clients_text.replace("example.com", DOMAIN)
    )
    shutil.copy(files["users.yml"], STACK / "users.yml")

    certs = STACK / "certs"
    cli.rsa_certificate(certs, f"*.{DOMAIN}", sans=(f"*.{DOMAIN}", DOMAIN))
    traefik = STACK / "traefik"
    traefik.mkdir()
    (traefik / "dynamic.yml").write_text(traefik_dynamic())
    for path in (STACK, managed, certs, traefik):
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
