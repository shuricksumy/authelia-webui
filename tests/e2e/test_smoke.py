from __future__ import annotations

import json
import subprocess

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.conftest import PORTAL_URL, compose, goto

pytestmark = pytest.mark.e2e


def test_authelia_portal_serves_login_page(stack: dict[str, str], page: Page) -> None:
    response = goto(page, PORTAL_URL, wait_until="networkidle")
    assert response is not None and response.ok
    expect(page).to_have_title("Login - Authelia")
    expect(page.get_by_role("textbox", name="Username")).to_be_visible()
    expect(page.get_by_role("textbox", name="Password")).to_be_visible()


def test_configurator_is_healthy_and_publishes_no_ports(stack: dict[str, str]) -> None:
    for service in ("configurator", "configurator-locked"):
        cid = compose("ps", "-q", service, env=stack).stdout.strip()
        health = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Health.Status}}", cid],
            capture_output=True, text=True, check=True,
        ).stdout.strip()  # fmt: skip
        assert health == "healthy", service
        ports = subprocess.run(
            ["docker", "inspect", "-f", "{{json .NetworkSettings.Ports}}", cid],
            capture_output=True, text=True, check=True,
        ).stdout.strip()  # fmt: skip
        published = json.loads(ports) or {}
        # nothing on the host, except the configurator's emergency port, on loopback only
        allowed = {"8090/tcp"} if service == "configurator" else set()
        assert {k for k, v in published.items() if v} == allowed, (service, ports)
        for bindings in published.values():
            assert all(b["HostIp"] == "127.0.0.1" for b in bindings or []), (service, ports)
