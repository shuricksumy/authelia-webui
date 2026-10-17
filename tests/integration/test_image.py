"""The built image: bundled Authelia matches the pin, fails closed, runs hardened."""

from __future__ import annotations

import secrets
import subprocess
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
TAG = "authelia-configurator:itest"
ENV = {
    "AUTH_DOMAIN": "auth.example.com",
    "CONFIGURATOR_DOMAIN": "authcfg.example.com",
    "ADMIN_GROUP": "admin",
    "ALLOWED_CLIENT_CIDRS": "10.8.0.0/24",
    "TRUSTED_PROXY_CIDRS": "172.20.0.0/16",
    "AUTHELIA_CONTAINER": "authelia",
    "AUTHELIA_HEALTH_URL": "http://authelia:9091/api/health",
}


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check)


def env_args(**overrides: str | None) -> list[str]:
    env = {**ENV, "APP_SECRET_KEY": secrets.token_urlsafe(48), **overrides}
    return [x for k, v in env.items() if v is not None for x in ("-e", f"{k}={v}")]


@pytest.fixture(scope="module")
def image(authelia_version: str, cli: object) -> str:
    docker("build", "-t", TAG, "--build-arg", f"AUTHELIA_VERSION={authelia_version}", str(ROOT))
    return TAG


def test_bundled_authelia_matches_pin_and_label(image: str, authelia_version: str) -> None:
    out = docker("run", "--rm", "--entrypoint", "authelia", image, "--version").stdout
    assert authelia_version in out
    label = docker(
        "image",
        "inspect",
        image,
        "-f",
        '{{index .Config.Labels "org.opencontainers.image.authelia-version"}}',
    ).stdout.strip()
    assert label == authelia_version


@pytest.mark.parametrize("missing", ["ALLOWED_CLIENT_CIDRS", "APP_SECRET_KEY"])
def test_refuses_to_start_without_required_variable(image: str, missing: str) -> None:
    args = env_args(**{missing: None})  # None drops the variable entirely
    proc = docker("run", "--rm", *args, image, check=False)
    assert proc.returncode != 0
    assert missing in proc.stderr + proc.stdout


def test_runs_hardened_and_reports_healthy(image: str) -> None:
    name = f"cfg-itest-{secrets.token_hex(4)}"
    docker(
        "run", "-d", "--name", name, "--read-only", "--tmpfs", "/tmp",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", *env_args(), image,
    )  # fmt: skip
    try:
        status = ""
        for _ in range(40):
            status = docker("inspect", "-f", "{{.State.Health.Status}}", name).stdout.strip()
            if status == "healthy":
                break
            time.sleep(1)
        assert status == "healthy", docker("logs", name).stderr
        assert docker("exec", name, "id", "-u").stdout.strip() == "10001"
    finally:
        docker("rm", "-f", name, check=False)


def test_the_key_move_runs_from_the_image(
    image: str, generated: dict[str, Path], tmp_path: Path
) -> None:
    """docs/jwks.md: the one-time move is a `docker run` of this image, like the split."""
    import os
    import shutil

    from scripts.split_config import split

    config = tmp_path / "config"
    (config / "managed").mkdir(parents=True)
    main = config / "configuration.yml"
    main.write_text(split(generated["configuration.yml"].read_text()).main_text)
    shutil.copymode(generated["configuration.yml"], main)
    proc = docker(
        "run", "--rm", "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}",
        "-v", f"{config}:/config", image,
        "python", "-m", "scripts.migrate_jwks",
        "--config", "/config/configuration.yml", "--managed", "/config/managed",
        check=False,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    assert "BEGIN" not in proc.stdout + proc.stderr  # no key material printed
    assert (config / "managed" / "oidc_jwks.yml").is_file()
    assert list((config / "managed" / "secrets" / "jwks").glob("*.pem"))
    assert "/config/managed/secrets/jwks/" in (config / "managed" / "oidc_jwks.yml").read_text()
