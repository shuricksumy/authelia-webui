"""Names (only names) from the main config's OIDC provider section, for the editor's choices.

The main file holds secrets inline (hmac_secret, jwks keys and certificates). Nothing but the
key names of authorization_policies, claims_policies and scopes ever leaves this module, so no
value can reach a template, a log or a page (SPEC §5).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

STANDARD_SCOPES = ("openid", "profile", "email", "groups", "offline_access", "address", "phone")
BUILTIN_POLICIES = ("one_factor", "two_factor")


@dataclass(frozen=True)
class OidcNames:
    configured: bool  # the main config has identity_providers.oidc
    authorization_policies: tuple[str, ...]  # built-ins first, then custom
    claims_policies: tuple[str, ...]
    scopes: tuple[str, ...]  # standard first, then custom

    @property
    def custom_scopes(self) -> tuple[str, ...]:
        return tuple(s for s in self.scopes if s not in STANDARD_SCOPES)


def _names(section: object) -> list[str]:
    return [str(k) for k in section] if isinstance(section, dict) else []


def load_oidc_names(main_config: Path) -> OidcNames:
    try:
        data = YAML(typ="safe", pure=True).load(main_config.read_text())
    except (OSError, YAMLError):
        return OidcNames(False, BUILTIN_POLICIES, (), STANDARD_SCOPES)
    providers = data.get("identity_providers") if isinstance(data, dict) else None
    oidc = providers.get("oidc") if isinstance(providers, dict) else None
    if not isinstance(oidc, dict):
        return OidcNames(False, BUILTIN_POLICIES, (), STANDARD_SCOPES)
    custom_policies = [
        n for n in _names(oidc.get("authorization_policies")) if n not in BUILTIN_POLICIES
    ]
    custom_scopes = [n for n in _names(oidc.get("scopes")) if n not in STANDARD_SCOPES]
    return OidcNames(
        True,
        (*BUILTIN_POLICIES, *custom_policies),
        tuple(_names(oidc.get("claims_policies"))),
        (*STANDARD_SCOPES, *custom_scopes),
    )
