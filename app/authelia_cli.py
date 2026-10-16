"""The only place that executes the Authelia binary.

Hashing, randomness and validation are always delegated to Authelia itself
(CLAUDE.md hard rule). Two runners:
- local: the binary bundled in the image (`/usr/local/bin/authelia`);
- docker: `docker run authelia/authelia:<version>` for host-side scripts/tests,
  with the needed directories bind-mounted at identical paths.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_TIMEOUT_S = 60

_REDACTIONS = [
    (re.compile(r"\$(argon2id?|pbkdf2[-\w]*|scrypt|bcrypt|sha512|2[aby])\$\S+"), "<hash>"),
    (re.compile(r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", re.S), "<pem>"),
]


def redact(text: str) -> str:
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


class AutheliaCLIError(RuntimeError):
    pass


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    raw: str = ""


_SECTION = re.compile(r"configuration parsed and loaded with (errors|warnings):", re.I)


def parse_validate_output(returncode: int, output: str) -> ValidationResult:
    """Parse `authelia config validate` output into errors and warnings.

    Measured against the pinned version (docs/merge-behaviour.md): sections are
    headed "Configuration parsed and loaded with errors:" / "...with warnings:",
    each followed by lines "\t - message". Messages can repeat; the CLI also
    prints a usage dump and a trailing "Error: ..." line, which are ignored.
    """
    errors: list[str] = []
    warnings: list[str] = []
    bucket: list[str] | None = None
    for line in output.splitlines():
        stripped = line.strip()
        section = _SECTION.search(stripped)
        if section:
            bucket = errors if section.group(1).lower() == "errors" else warnings
        elif stripped.startswith("- ") and bucket is not None:
            message = stripped[2:].strip()
            if message not in bucket:
                bucket.append(message)
        elif not stripped or stripped.startswith("Error:"):
            bucket = None if stripped.startswith("Error:") else bucket
    if returncode != 0 and not errors:
        errors.append(f"authelia exited with status {returncode}")
    return ValidationResult(
        ok=returncode == 0 and not errors, errors=errors, warnings=warnings, raw=redact(output)
    )


@dataclass(frozen=True)
class AutheliaCLI:
    argv_prefix: tuple[str, ...]
    docker: bool = False
    timeout_s: int = DEFAULT_TIMEOUT_S

    @classmethod
    def local(cls, binary: str = "authelia") -> AutheliaCLI:
        return cls(argv_prefix=(binary,))

    @classmethod
    def via_docker(cls, version: str) -> AutheliaCLI:
        return cls(argv_prefix=(f"authelia/authelia:{version}", "authelia"), docker=True)

    def _argv(self, args: Sequence[str], mounts: Sequence[Path], writable: bool) -> list[str]:
        if not self.docker:
            return [*self.argv_prefix, *args]
        # Run as the calling user: files the container writes (keys) stay readable by us on
        # Linux, where bind mounts keep the container's uid (root by default).
        user = f"{os.getuid()}:{os.getgid()}"
        argv = ["docker", "run", "--rm", "--network", "none", "--user", user, "--entrypoint", ""]
        mode = "rw" if writable else "ro"
        for directory in sorted({m.resolve() for m in mounts}):
            argv += ["-v", f"{directory}:{directory}:{mode}"]
        return [*argv, *self.argv_prefix, *args]

    def run(
        self, args: Sequence[str], *, mounts: Sequence[Path] = (), writable: bool = False
    ) -> subprocess.CompletedProcess[str]:
        argv = self._argv(args, mounts, writable)
        try:
            return subprocess.run(
                argv, capture_output=True, text=True, timeout=self.timeout_s, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AutheliaCLIError(f"could not run authelia: {type(exc).__name__}") from None

    def validate(self, paths: Sequence[Path]) -> ValidationResult:
        resolved = [p.resolve() for p in paths]
        args = ["config", "validate"]
        for path in resolved:
            args += ["--config", str(path)]
        proc = self.run(args, mounts=[p.parent for p in resolved])
        return parse_validate_output(proc.returncode, proc.stdout + proc.stderr)

    def version(self) -> str:
        proc = self.run(["--version"])
        if proc.returncode != 0:
            raise AutheliaCLIError("authelia --version failed")
        match = re.search(r"v?(\d+\.\d+\.\d+)", proc.stdout)
        if not match:
            raise AutheliaCLIError("could not parse authelia version")
        return match.group(1)

    def rand(self, length: int = 64, charset: str = "alphanumeric") -> str:
        proc = self.run(["crypto", "rand", "--length", str(length), "--charset", charset])
        return _value_after_colon(proc, "crypto rand")

    def hash_pbkdf2(self, password: str) -> str:
        proc = self.run(
            ["crypto", "hash", "generate", "pbkdf2", "--variant", "sha512", "--password", password]
        )
        return _value_after_colon(proc, "crypto hash generate pbkdf2")

    def hash_argon2(self, password: str) -> str:
        proc = self.run(["crypto", "hash", "generate", "argon2", "--password", password])
        return _value_after_colon(proc, "crypto hash generate argon2")

    def rsa_certificate(self, directory: Path, common_name: str) -> tuple[Path, Path]:
        directory.mkdir(parents=True, exist_ok=True)
        proc = self.run(
            [
                "crypto", "certificate", "rsa", "generate",
                "--common-name", common_name,
                "--directory", str(directory.resolve()),
            ],
            mounts=[directory],
            writable=True,
        )  # fmt: skip
        if proc.returncode != 0:
            raise AutheliaCLIError("crypto certificate rsa generate failed")
        return directory / "private.pem", directory / "public.crt"


def _value_after_colon(proc: subprocess.CompletedProcess[str], what: str) -> str:
    """Authelia prints e.g. 'Random Value: xyz' / 'Digest: $...'. Never log the value."""
    if proc.returncode != 0:
        raise AutheliaCLIError(f"{what} failed")
    for line in proc.stdout.splitlines():
        if ":" in line:
            value = line.split(":", 1)[1].strip()
            if value:
                return value
    raise AutheliaCLIError(f"{what}: unexpected output format")
