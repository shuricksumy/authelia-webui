"""Prepare the compose test stack's /config directory (gitignored).

Generates the realistic config with real secrets, then splits it with our own
migration script, so the stack runs exactly the layout the app manages in production.

    uv run python -m tests.fixtures.stack [--authelia docker:<version>|local]
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from scripts.split_config import (
    ACCESS_CONTROL_NAME,
    MAIN_NAME,
    OIDC_CLIENTS_NAME,
    check_structural_equality,
    split,
)
from tests.fixtures.generate import GENERATED, generate, make_cli

STACK = GENERATED / "stack"
X_AUTHELIA_CONFIG = ",".join(
    [
        "/config/configuration.yml",
        f"/config/managed/{ACCESS_CONTROL_NAME}",
        f"/config/managed/{OIDC_CLIENTS_NAME}",
    ]
)


def prepare(authelia: str = "auto") -> Path:
    files = generate(make_cli(authelia))
    original = files["configuration.yml"].read_text()
    result = split(original)
    check_structural_equality(original, result)
    managed = STACK / "managed"
    managed.mkdir(parents=True)
    (STACK / "configuration.yml").write_text(result.main_text)
    (managed / ACCESS_CONTROL_NAME).write_text(result.access_control_text)
    assert result.oidc_clients_text is not None
    (managed / OIDC_CLIENTS_NAME).write_text(result.oidc_clients_text)
    shutil.copy(files["users.yml"], STACK / "users.yml")
    assert MAIN_NAME  # imported for documentation of the naming contract
    return STACK


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--authelia", default="auto")
    print("stack ready:", prepare(parser.parse_args().authelia))
