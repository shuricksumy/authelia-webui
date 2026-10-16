from __future__ import annotations

import subprocess

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.conftest import PORTAL_URL, compose

pytestmark = pytest.mark.e2e


def test_authelia_portal_serves_login_page(stack: dict[str, str], page: Page) -> None:
    response = page.goto(PORTAL_URL, wait_until="networkidle")
    assert response is not None and response.ok
    expect(page).to_have_title("Login - Authelia")
    expect(page.get_by_role("textbox", name="Username")).to_be_visible()
    expect(page.get_by_role("textbox", name="Password")).to_be_visible()


def test_configurator_is_healthy_and_publishes_no_ports(stack: dict[str, str]) -> None:
    ps = compose("ps", "--format", "{{.Service}} {{.Health}} {{.Publishers}}", env=stack)
    rows = {line.split()[0]: line for line in ps.stdout.splitlines() if line.strip()}
    assert "healthy" in rows["configurator"]
    cid = compose("ps", "-q", "configurator", env=stack).stdout.strip()
    ports = subprocess.run(
        ["docker", "inspect", "-f", "{{json .NetworkSettings.Ports}}", cid],
        capture_output=True, text=True, check=True,
    ).stdout.strip()  # fmt: skip
    assert ports in {"{}", "null", '{"8080/tcp":null}'}, ports  # nothing bound on the host
