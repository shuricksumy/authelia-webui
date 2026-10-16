from __future__ import annotations

import os
from pathlib import Path

from app.authelia_cli import AutheliaCLI, parse_validate_output, redact

ERRORS = """Configuration parsed and loaded with errors:

\t - access_control: option 'default_policy' must be one of 'bypass' but it's configured as 'x'
\t - access_control: option 'default_policy' must be one of 'bypass' but it's configured as 'x'
\t - session: option 'cookies' is required

Error: configuration validation failed
Usage:
  authelia config validate [flags]
Flags:
  -h, --help   help for validate
"""

BOTH = """Configuration parsed and loaded with warnings:

\t - configuration keys 'server.host' are deprecated in 4.38.0

Configuration parsed and loaded with errors:

\t - storage: option 'encryption_key' is required
"""


def test_parses_errors_dedupes_and_ignores_usage_dump() -> None:
    res = parse_validate_output(1, ERRORS)
    assert not res.ok
    assert len(res.errors) == 2 and not res.warnings
    assert not any("Usage" in e or "Flags" in e for e in res.errors)


def test_parses_warnings_and_errors_in_any_order() -> None:
    res = parse_validate_output(1, BOTH)
    assert res.errors == ["storage: option 'encryption_key' is required"]
    assert len(res.warnings) == 1 and "deprecated" in res.warnings[0]


def test_success_with_warnings_is_ok() -> None:
    res = parse_validate_output(0, BOTH.split("Configuration parsed and loaded with errors")[0])
    assert res.ok and res.warnings


def test_nonzero_exit_without_parsable_errors_still_fails() -> None:
    res = parse_validate_output(2, "something unexpected")
    assert not res.ok and "status 2" in res.errors[0]


def test_redact_hashes_and_pem() -> None:
    hash_ = "$" + "argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"
    pem = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"  # hygiene: ignore
    out = redact(f"x {hash_} y {pem} z")
    assert hash_ not in out and "AAAA" not in out and "<hash>" in out and "<pem>" in out


def test_docker_runner_is_offline_and_mounts_readonly(tmp_path: Path) -> None:
    cli = AutheliaCLI.via_docker("1.2.3")
    argv = cli._argv(["config", "validate"], [tmp_path], writable=False)
    assert argv[:3] == ["docker", "run", "--rm"]
    assert "none" in argv and argv[argv.index("--network") + 1] == "none"
    assert f"{tmp_path.resolve()}:{tmp_path.resolve()}:ro" in argv
    assert "-v" in argv and "/var/run/docker.sock" not in " ".join(argv)
    # Generated key files must belong to the caller, not root (Linux bind mounts).
    assert argv[argv.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
