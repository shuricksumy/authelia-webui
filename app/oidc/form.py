"""Form model for one OIDC client (SPEC §5 table, §15.7 sections).

- Only keys the user changed are written, so untouched values keep their quoting.
- "absent", "" and false are different things in Authelia's config (real configs use
  `pkce_challenge_method: ''` and `require_pkce: false`), so every optional scalar has an explicit
  "(not set)" choice (UNSET) instead of mapping "" to absent.
- `client_secret` is never part of the form: the hash is kept from the existing client and only
  changed by the secret endpoint. The raw YAML tab cannot set it either.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.error import YAMLError

from app.blocklist import DocumentError, rt_yaml

UNSET = "__unset__"

GRANT_TYPES = ("authorization_code", "refresh_token", "client_credentials", "implicit")
RESPONSE_TYPES = ("code", "id_token", "token", "code id_token", "code token", "id_token token",
                  "code id_token token")  # fmt: skip
RESPONSE_MODES = ("form_post", "query", "fragment")
AUTH_METHODS = ("client_secret_basic", "client_secret_post", "client_secret_jwt",
                "private_key_jwt", "none")  # fmt: skip
PKCE_METHODS = ("S256", "plain")
CONSENT_MODES = ("auto", "explicit", "implicit", "pre-configured")
SIGNING_ALGS = ("none", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384",
                "PS512")  # fmt: skip
SIGNED_RESPONSE_KEYS = (
    "id_token_signed_response_alg",
    "userinfo_signed_response_alg",
    "access_token_signed_response_alg",
    "introspection_signed_response_alg",
    "authorization_signed_response_alg",
)

SCALARS = ("client_name", "authorization_policy", "claims_policy", "token_endpoint_auth_method",
           "pkce_challenge_method", "consent_mode", "pre_configured_consent_duration",
           *SIGNED_RESPONSE_KEYS)  # fmt: skip
LISTS = ("redirect_uris", "scopes", "grant_types", "response_types", "response_modes")
BOOLS = ("public", "require_pkce")
KNOWN = ("client_id", "client_secret", *SCALARS, *LISTS, *BOOLS)


class FormError(ValueError):
    """The submitted form cannot be turned into a client; message is safe to show."""


@dataclass
class ClientForm:
    client_id: str = ""
    scalars: dict[str, str] = field(default_factory=dict)  # key -> value, UNSET, or "" (empty)
    lists: dict[str, list[str] | None] = field(default_factory=dict)  # None = absent
    bools: dict[str, str] = field(default_factory=dict)  # "true" | "false" | UNSET
    extra_yaml: str = ""  # keys this form does not know, as YAML (never client_secret)

    @classmethod
    def from_data(cls, data: dict[str, Any]) -> ClientForm:
        def scalar(key: str) -> str:
            return UNSET if key not in data or data[key] is None else str(data[key])

        def listed(key: str) -> list[str] | None:
            if key not in data or data[key] is None:
                return None
            value = data[key]
            return [str(v) for v in value] if isinstance(value, list) else [str(value)]

        def boolean(key: str) -> str:
            return UNSET if key not in data else ("true" if data[key] is True else "false")

        extra = {k: v for k, v in data.items() if k not in KNOWN}
        return cls(
            client_id=str(data.get("client_id") or ""),
            scalars={k: scalar(k) for k in SCALARS},
            lists={k: listed(k) for k in LISTS},
            bools={k: boolean(k) for k in BOOLS},
            extra_yaml=_dump(extra) if extra else "",
        )

    @property
    def public(self) -> bool:
        return self.bools.get("public") == "true"


def _dump(data: dict[str, Any]) -> str:
    yaml = YAML(typ="rt")
    yaml.indent(mapping=2, sequence=4, offset=2)
    buf = io.StringIO()
    yaml.dump(data, buf)
    return buf.getvalue().rstrip("\n")


def parse_extra(text: str) -> dict[str, Any]:
    if not text.strip():
        return {}
    try:
        data = rt_yaml().load(text)
    except YAMLError:
        raise FormError("The raw YAML is not valid.") from None
    if not isinstance(data, dict):
        raise FormError("The raw YAML must be a mapping of extra keys.")
    clash = sorted(set(map(str, data)) & set(KNOWN))
    if clash:
        raise FormError(
            "The raw YAML may only hold keys the form does not have; move these to the form: "
            + ", ".join(clash)
            + "."
        )
    return dict(data)


def apply_client_form(form: ClientForm, base: CommentedMap | None = None) -> CommentedMap:
    """The client mapping: `base` (round-trip node of the existing client) with the form applied.
    The secret hash in `base` is kept as it is; a new client has none (the caller generates it)."""
    node = base if base is not None else CommentedMap()
    client_id = form.client_id.strip()
    if not client_id:
        raise FormError("client_id is required.")
    if any(c.isspace() for c in client_id):
        raise FormError("client_id must not contain spaces.")
    _set(node, "client_id", client_id)

    for key in BOOLS:
        value = form.bools.get(key, UNSET)
        if value == UNSET:
            node.pop(key, None)
        else:
            _set(node, key, value == "true")
    for key in SCALARS:
        value = form.scalars.get(key, UNSET)
        if value == UNSET:
            node.pop(key, None)
        else:
            _set(node, key, value.strip())
    for key in LISTS:
        items = form.lists.get(key)
        if items is None:
            node.pop(key, None)
        else:
            # checkbox groups come back in page order, not file order: an unchanged set keeps
            # the file's order (and so its diff); only redirect_uris is order-sensitive text
            _set(node, key, [i.strip() for i in items if i.strip()],
                 unordered=key != "redirect_uris")  # fmt: skip

    extra = parse_extra(form.extra_yaml)
    for key in [k for k in node if k not in KNOWN and k not in extra]:
        del node[key]
    for key, value in extra.items():
        _set(node, key, value)
    if form.public:
        node.pop("client_secret", None)  # a public client has no secret (lint would block it)
    return node


def _set(node: CommentedMap, key: str, value: Any, unordered: bool = False) -> None:
    """Assign only when the value really changes, so quoting and comments of untouched keys
    survive the round trip. With `unordered`, the same members in another order are no change."""
    if key in node:
        old, new = _plain(node[key]), _plain(value)
        if old == new:
            return
        same_members = (
            isinstance(old, list) and isinstance(new, list)
            and sorted(map(str, old)) == sorted(map(str, new))
        )  # fmt: skip
        if unordered and same_members:
            return
    node[key] = value


def _plain(value: Any) -> Any:
    if isinstance(value, list):
        return [_plain(v) for v in value]
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return str(value)
    return value


def check(form: ClientForm) -> None:
    """Cheap structural checks before lint (lint has the semantic ones)."""
    for key in ("grant_types", "response_types", "response_modes"):
        allowed = {"grant_types": GRANT_TYPES, "response_types": RESPONSE_TYPES,
                   "response_modes": RESPONSE_MODES}[key]  # fmt: skip
        unknown = [v for v in form.lists.get(key) or [] if v not in allowed]
        if unknown:
            raise FormError(f"Unknown {key.replace('_', ' ')}: {', '.join(unknown)}.")
    method = form.scalars.get("token_endpoint_auth_method", UNSET)
    if method not in (UNSET, *AUTH_METHODS):
        raise FormError(f"Unknown token endpoint auth method: {method}.")


__all__ = [
    "AUTH_METHODS",
    "CONSENT_MODES",
    "GRANT_TYPES",
    "PKCE_METHODS",
    "RESPONSE_MODES",
    "RESPONSE_TYPES",
    "SIGNED_RESPONSE_KEYS",
    "SIGNING_ALGS",
    "UNSET",
    "ClientForm",
    "DocumentError",
    "FormError",
    "apply_client_form",
    "check",
    "parse_extra",
]
