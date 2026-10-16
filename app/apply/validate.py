"""Ask the bundled Authelia whether main config + a candidate access_control + OIDC clients
validate. Read-only: the candidate is written to a private temp dir, never to the live file."""

from __future__ import annotations

import tempfile
from pathlib import Path

from app.authelia_cli import AutheliaCLI, AutheliaCLIError, ValidationResult, redact
from app.settings import Settings


def validate_candidate(
    settings: Settings, access_control_text: str, clients_text: str | None = None
) -> ValidationResult | None:
    """Validate main config + candidate rules + candidate OIDC clients (None: the live clients
    file, if any). None when the validator cannot run (binary missing): callers must treat that
    as 'unknown'. The temp dir is private and removed; it may hold client secret hashes."""
    try:
        cli = AutheliaCLI.local(settings.AUTHELIA_BINARY)
        with tempfile.TemporaryDirectory(prefix="validate-") as tmp:
            candidate = Path(tmp) / "access_control.yml"
            candidate.write_text(access_control_text)
            candidate.chmod(0o600)
            paths = [settings.CONFIG_MAIN, candidate]
            if clients_text is not None:
                clients = Path(tmp) / "oidc_clients.yml"
                clients.write_text(clients_text)
                clients.chmod(0o600)
                paths.append(clients)
            elif (settings.CONFIG_MANAGED_DIR / "oidc_clients.yml").is_file():
                paths.append(settings.CONFIG_MANAGED_DIR / "oidc_clients.yml")
            result = cli.validate(paths)
        return ValidationResult(
            result.ok, [redact(e) for e in result.errors], [redact(w) for w in result.warnings], ""
        )
    except (AutheliaCLIError, OSError):
        return None
