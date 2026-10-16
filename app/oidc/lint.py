"""Plain-language checks for OIDC clients (SPEC §5 "Rules"). Errors block saving the client and
applying; warnings do not. Authelia's own validator runs as well (review and apply)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

from app.oidc.document import secret_kind
from app.oidc.names import OidcNames
from app.rules.lint import Issue

SECRET_METHODS = ("client_secret_basic", "client_secret_post", "client_secret_jwt")
LOOPBACK = ("localhost", "127.0.0.1", "[::1]", "::1")


def _list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def is_public(client: Mapping[str, Any]) -> bool:
    return client.get("public") is True


def auth_method(client: Mapping[str, Any]) -> str:
    """Authelia's default: `none` for public clients, `client_secret_basic` otherwise."""
    value = client.get("token_endpoint_auth_method")
    if value:
        return str(value)
    return "none" if is_public(client) else "client_secret_basic"


def redirect_problem(uri: str) -> tuple[str, str] | None:
    """(severity, message) for one redirect URI, or None when it is fine."""
    parts = urlsplit(uri)
    if not parts.scheme:
        return "error", f"redirect URI '{uri}' is not absolute"
    if parts.fragment or "#" in uri:
        return "error", f"redirect URI '{uri}' must not contain a fragment (#)"
    if parts.scheme in ("http", "https"):
        if not parts.hostname:
            return "error", f"redirect URI '{uri}' has no host"
        if parts.scheme == "http" and parts.hostname not in LOOPBACK:
            return "warning", f"redirect URI '{uri}' is not https"
    return None  # a custom scheme (native app), e.g. app.immich:///oauth-callback


def lint_client(
    index: int, client: Mapping[str, Any], names: OidcNames, all_ids: Sequence[str] = ()
) -> list[Issue]:
    out: list[Issue] = []

    def add(severity: str, code: str, message: str) -> None:
        out.append(Issue(index, severity, code, message))

    client_id = str(client.get("client_id") or "").strip()
    label = f"Client '{client_id}'" if client_id else f"Client #{index + 1}"
    if not client_id:
        add("error", "no-client-id", f"{label} has no client_id.")
    elif list(all_ids).count(client_id) > 1:
        add("error", "duplicate-client-id", f"{label}: client_id is used by another client.")

    public = is_public(client)
    kind = secret_kind(client.get("client_secret"))
    method = auth_method(client)
    if public and kind:
        add("error", "public-with-secret", f"{label} is public but has a client secret.")
    if public and method != "none":
        add(
            "error",
            "public-auth-method",
            f"{label} is public, so its token endpoint auth method must be 'none' (is '{method}').",
        )
    if not public and method == "none":
        add(
            "error",
            "confidential-auth-none",
            f"{label} is confidential but its token endpoint auth method is 'none'.",
        )
    if not public and not kind and method in SECRET_METHODS:
        add(
            "error",
            "confidential-without-secret",
            f"{label} is confidential but has no client secret. Generate one.",
        )
    if kind == "plaintext":
        add(
            "warning",
            "plaintext-secret",
            f"{label}: the client secret is stored in plain text. Generate a new one (only a "
            "hash is stored).",
        )
    if public and client.get("require_pkce") is not True:
        add(
            "warning",
            "public-without-pkce",
            f"{label} is public but does not set require_pkce: true.",
        )

    uris = _list(client.get("redirect_uris"))
    if not uris and "authorization_code" in _list(
        client.get("grant_types") or ["authorization_code"]
    ):
        add("error", "no-redirect-uri", f"{label} has no redirect URI.")
    for uri in uris:
        problem = redirect_problem(uri)
        if problem:
            add(problem[0], "redirect-uri", f"{label}: {problem[1]}.")

    if names.configured:
        policy = client.get("authorization_policy")
        if policy and str(policy) not in names.authorization_policies:
            add(
                "error",
                "unknown-policy",
                f"{label}: authorization policy '{policy}' is not defined in the main config.",
            )
        claims = client.get("claims_policy")
        if claims and str(claims) not in names.claims_policies:
            add(
                "error",
                "unknown-claims-policy",
                f"{label}: claims policy '{claims}' is not defined in the main config.",
            )
        for scope in _list(client.get("scopes")):
            if scope not in names.scopes:
                add(
                    "error",
                    "unknown-scope",
                    f"{label}: scope '{scope}' is neither standard nor defined in the main config.",
                )
    return out


def lint_clients(clients: Sequence[Mapping[str, Any]], names: OidcNames) -> list[Issue]:
    ids = [str(c.get("client_id") or "").strip() for c in clients]
    out: list[Issue] = []
    if not clients and names.configured:
        out.append(
            Issue(
                None,
                "error",
                "no-clients",
                "There must be at least one OIDC client: Authelia refuses an OpenID "
                "Connect provider without clients.",
            )
        )
    for i, client in enumerate(clients):
        out.extend(lint_client(i, client, names, ids))
    return out
