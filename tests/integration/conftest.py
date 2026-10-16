"""Integration fixtures: real Authelia at the pinned version (never mocked)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from app.authelia_cli import AutheliaCLI
from scripts.split_config import _dockerfile_version
from tests.fixtures.generate import generate

pytestmark = pytest.mark.integration


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)


@pytest.fixture(scope="session")
def authelia_version() -> str:
    return _dockerfile_version()


@pytest.fixture(scope="session")
def cli(authelia_version: str) -> AutheliaCLI:
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    if subprocess.run(["docker", "info"], capture_output=True, check=False).returncode != 0:
        pytest.skip("docker daemon not running")
    return AutheliaCLI.via_docker(authelia_version)


@pytest.fixture(scope="session")
def generated(cli: AutheliaCLI, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """Realistic config with real generated secrets, in a temp dir (never in git)."""
    return generate(cli, tmp_path_factory.mktemp("generated"))
