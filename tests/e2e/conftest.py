"""Compose test stack for e2e: Traefik + Authelia (split config) + the configurator image."""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from playwright.sync_api import Browser, BrowserContext, Page

from scripts.split_config import _dockerfile_version
from tests.e2e.auth import BASE, login
from tests.fixtures.stack import AUTH_HOST, PORTAL_PORT, STACK, prepare

ROOT = Path(__file__).resolve().parents[2]
PORTAL_URL = f"https://{AUTH_HOST}:{PORTAL_PORT}"
RESOLVER = "--host-resolver-rules=MAP *.example.test 127.0.0.1"


def stack_env() -> dict[str, str]:
    return {
        **os.environ,
        "AUTHELIA_VERSION": _dockerfile_version(),
        "TEST_APP_SECRET_KEY": secrets.token_urlsafe(48),
        "DEV_UID": str(os.getuid()),
        "DEV_GID": str(os.getgid()),
    }


def compose(*args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "-f", str(ROOT / "compose.test.yml"), *args],
        capture_output=True, text=True, check=False, env=env, cwd=ROOT,
    )  # fmt: skip


@pytest.fixture(scope="session")
def browser_type_launch_args(browser_type_launch_args: dict[str, Any]) -> dict[str, Any]:
    """Resolve *.example.test to the local Traefik without touching /etc/hosts."""
    return {**browser_type_launch_args, "args": [RESOLVER]}


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args: dict[str, Any]) -> dict[str, Any]:
    """The stack uses a self-signed wildcard certificate for *.example.test."""
    return {**browser_context_args, "ignore_https_errors": True}


@pytest.fixture(scope="session")
def stack() -> Iterator[dict[str, str]]:
    if subprocess.run(["docker", "info"], capture_output=True, check=False).returncode != 0:
        pytest.skip("docker daemon not running")
    prepare()
    env = stack_env()
    up = compose("up", "-d", "--build", "--wait", "--wait-timeout", "240", env=env)
    try:
        assert up.returncode == 0, up.stderr[-2000:]
        yield env
    finally:
        compose("down", "-v", "--remove-orphans", env=env)


@pytest.fixture(scope="session")
def alice_state(stack: dict[str, str], browser: Browser) -> dict[str, Any]:
    """One real login (password + TOTP) shared by the tests that need an admin session."""
    return login(browser)


@pytest.fixture(autouse=True)
def clean_draft(stack: dict[str, str]) -> Iterator[None]:
    shutil.rmtree(STACK / "managed" / ".draft", ignore_errors=True)
    yield
    shutil.rmtree(STACK / "managed" / ".draft", ignore_errors=True)


@pytest.fixture
def admin(browser: Browser, alice_state: dict[str, Any]) -> Iterator[Page]:
    context: BrowserContext = browser.new_context(
        ignore_https_errors=True, storage_state=alice_state,  # type: ignore[arg-type]
        viewport={"width": 1280, "height": 900},
    )  # fmt: skip
    page = context.new_page()
    yield page
    context.close()


def live_rules() -> list[dict[str, Any]]:
    """The rules the stack started with (numbers in assertions derive from this, not literals)."""
    from app.rules.document import RulesDocument

    return RulesDocument.parse((STACK / "managed" / "access_control.yml").read_text()).rules()


def rule_number(domain: str, policy: str) -> int:
    """1-based position of the first live rule with this domain and policy."""
    for i, rule in enumerate(live_rules()):
        if rule.get("domain") == domain and rule.get("policy") == policy:
            return i + 1
    raise LookupError(domain)


def open_rules(page: Page) -> None:
    page.goto(f"{BASE}/rules", wait_until="networkidle")
