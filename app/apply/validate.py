"""Ask the bundled Authelia whether main config + a candidate access_control + OIDC clients
validate. Read-only: the candidate is written to a private temp dir, never to the live file."""

from __future__ import annotations

import tempfile
from pathlib import Path

from app.authelia_cli import AutheliaCLI, AutheliaCLIError, ValidationResult, redact
from app.settings import Settings


def validate_candidate(settings: Settings, access_control_text: str) -> ValidationResult | None:
    """None when the validator cannot run (binary missing): callers must treat that as 'unknown'."""
    try:
        cli = AutheliaCLI.local(settings.AUTHELIA_BINARY)
        with tempfile.TemporaryDirectory(prefix="validate-") as tmp:
            candidate = Path(tmp) / "access_control.yml"
            candidate.write_text(access_control_text)
            candidate.chmod(0o600)
            paths = [settings.CONFIG_MAIN, candidate]
            clients = settings.CONFIG_MANAGED_DIR / "oidc_clients.yml"
            if clients.is_file():
                paths.append(clients)
            result = cli.validate(paths)
        return ValidationResult(
            result.ok, [redact(e) for e in result.errors], [redact(w) for w in result.warnings], ""
        )
    except (AutheliaCLIError, OSError):
        return None
