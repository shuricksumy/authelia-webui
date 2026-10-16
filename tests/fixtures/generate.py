"""Generate the realistic test config with real secrets/hashes/keys (never committed).

Reads tests/fixtures/realistic/*.example.yml, fills every __GEN_*__ placeholder using the
pinned Authelia binary, and writes tests/fixtures/generated/{configuration.yml,users.yml}.

    uv run python -m tests.fixtures.generate [--authelia docker:<version>|local]
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
import uuid
from pathlib import Path

from app.authelia_cli import AutheliaCLI
from scripts.split_config import _dockerfile_version

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "realistic"
GENERATED = ROOT / "generated"
PLACEHOLDER = re.compile(r"^([ \t]*)(.*?)(__GEN_[A-Z0-9_]+__)(.*)$")


def make_cli(mode: str) -> AutheliaCLI:
    if mode == "local" or (mode == "auto" and shutil.which("authelia")):
        return AutheliaCLI.local()
    version = mode.removeprefix("docker:") if mode.startswith("docker:") else _dockerfile_version()
    return AutheliaCLI.via_docker(version)


class Generator:
    def __init__(self, cli: AutheliaCLI, workdir: Path) -> None:
        self.cli = cli
        self.workdir = workdir
        self._cache: dict[str, str] = {}

    def _cached(self, name: str, make: object) -> str:
        if name not in self._cache:
            assert callable(make)
            self._cache[name] = make()
        return self._cache[name]

    def _rsa(self) -> tuple[str, str]:
        key_dir = self.workdir / "rsa"
        key, cert = self.cli.rsa_certificate(key_dir, "test-key-id")
        return key.read_text(), cert.read_text()

    def value(self, name: str) -> str:
        if name == "__GEN_SECRET_64__":
            return self.cli.rand(64)  # unique per occurrence
        if name == "__GEN_UUID__":
            return str(uuid.uuid4())
        if name == "__GEN_PBKDF2_HASH__":
            return self._cached(name, lambda: self.cli.hash_pbkdf2(self.cli.rand(24)))
        if name == "__GEN_ARGON2_HASH__":
            return self._cached(name, lambda: self.cli.hash_argon2(self.cli.rand(24)))
        if name in {"__GEN_RSA_PRIVATE_KEY_PEM__", "__GEN_RSA_CERT_PEM__"}:
            pair = self._cached("rsa", lambda: "\0".join(self._rsa()))
            private, cert = pair.split("\0")
            return (private if "PRIVATE" in name else cert).strip()
        raise ValueError(f"unknown placeholder {name}")

    def fill(self, text: str) -> str:
        out: list[str] = []
        for line in text.splitlines():
            match = PLACEHOLDER.match(line)
            if not match:
                out.append(line)
                continue
            indent, before, name, after = match.groups()
            value = self.value(name)
            if "\n" in value:  # block scalar: indent every line like the placeholder
                out.extend(f"{indent}{v}" for v in value.splitlines())
            else:
                out.append(f"{indent}{before}{value}{after}")
        return "\n".join(out) + "\n"


def generate(cli: AutheliaCLI, target: Path = GENERATED) -> dict[str, Path]:
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    gen = Generator(cli, target / ".work")
    produced = {}
    for src, dest in (
        ("main.example.yml", "configuration.yml"),
        ("users.example.yml", "users.yml"),
    ):
        path = target / dest
        path.write_text(gen.fill((SOURCE / src).read_text()))
        path.chmod(0o600)
        produced[dest] = path
    shutil.rmtree(target / ".work", ignore_errors=True)
    return produced


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--authelia", default="auto")
    files = generate(make_cli(parser.parse_args().authelia))
    print("generated:", ", ".join(str(p.relative_to(ROOT.parent.parent)) for p in files.values()))
    sys.exit(0)
