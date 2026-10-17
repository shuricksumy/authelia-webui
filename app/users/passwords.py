"""Setting a user's password (SPEC §9): generated (default) or typed, hashed by the bundled
Authelia with the main config's algorithm. The plaintext only ever goes to the browser once, in the
response that created it (generated) or comes from it (typed); it is never stored or logged."""

from __future__ import annotations

from pathlib import Path

from app.authelia_cli import AutheliaCLI, AutheliaCLIError
from app.users.schema import PasswordPolicy, policy_problems

GENERATE_ATTEMPTS = 8


class PasswordError(ValueError):
    """Plain-language reason; never contains the password."""


def generated(cli: AutheliaCLI, main_config: Path, policy: PasswordPolicy) -> tuple[str, str]:
    """(password, hash) made by Authelia, regenerated until it meets the standard policy."""
    length = max(20, policy.min_length)
    if policy.max_length:
        length = min(length, policy.max_length)
    for _ in range(GENERATE_ATTEMPTS):
        try:
            password, digest = cli.generate_password(main_config, length=length, charset="ascii")
        except AutheliaCLIError:
            raise PasswordError("Authelia could not generate a password here.") from None
        if policy.mode != "standard" or not policy_problems(password, policy):
            return password, digest
    raise PasswordError("Could not generate a password that meets the password policy.")


def typed(cli: AutheliaCLI, main_config: Path, password: str, policy: PasswordPolicy) -> str:
    """The hash of a password the admin typed, after checking it against the policy."""
    if policy.mode == "zxcvbn":
        raise PasswordError("Your password policy (zxcvbn) cannot be checked here; generate one.")
    problems = policy_problems(password, policy)
    if problems:
        raise PasswordError("The password needs " + ", ".join(problems) + ".")
    try:
        return cli.hash_password(password, main_config)
    except AutheliaCLIError:
        raise PasswordError("Authelia could not hash the password here.") from None
