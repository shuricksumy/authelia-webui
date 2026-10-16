"""App presets for new OIDC clients (SPEC §5 "Templates").

Each preset is a YAML file in app/oidc_templates/ holding what Authelia's integration guide for
that app says (checked against the 4.39 docs), with the placeholder host `app.example.com`.
Presets never carry a secret: a confidential client gets one generated when it is saved.
The user's app address replaces the placeholder and the user reviews everything before saving.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

DIRECTORY = Path(__file__).resolve().parent.parent / "oidc_templates"
PLACEHOLDER = "app.example.com"
GUIDE_BASE = "https://www.authelia.com/integration/openid-connect/clients/"
HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(:\d{1,5})?$")
ORDER = ("generic", "generic-public")


@dataclass(frozen=True)
class Template:
    id: str
    name: str
    description: str
    host_label: str
    client: dict[str, Any]
    guide: str = ""
    notes: str = ""
    needs: str = ""
    main_config: str = ""

    @property
    def guide_url(self) -> str:
        return f"{GUIDE_BASE}{self.guide}/" if self.guide else ""

    @property
    def needed_names(self) -> dict[str, str]:
        """{'claims_policy': 'cloudflare', ...}: names the client refers to that a preset adds."""
        out = {}
        if self.main_config:
            for key in ("claims_policy",):
                if self.client.get(key):
                    out[key] = str(self.client[key])
            custom = [s for s in self.client.get("scopes", []) if s not in STANDARD]
            if custom:
                out["scope"] = ", ".join(custom)
        return out

    def instantiate(self, host: str = "") -> dict[str, Any]:
        """The client mapping, with the user's host in the redirect URIs."""
        client = {"client_id": self.id, **_copy(self.client)}
        if host:
            client["redirect_uris"] = [
                u.replace(PLACEHOLDER, host) for u in client["redirect_uris"]
            ]
        return client


STANDARD = ("openid", "profile", "email", "groups", "offline_access", "address", "phone")


def _copy(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _copy(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_copy(v) for v in value]
    return value


def clean_host(text: str) -> str | None:
    """host[:port] from what the user typed (a pasted URL is fine); None when it is not one."""
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text.strip(), flags=re.I).split("/", 1)[0]
    return value if value and HOST.match(value) else None


@cache
def load_all() -> tuple[Template, ...]:
    yaml = YAML(typ="safe", pure=True)
    found = []
    for path in sorted(DIRECTORY.glob("*.yml")):
        data = yaml.load(path.read_text())
        found.append(Template(
            id=path.stem, name=str(data["name"]), description=str(data["description"]),
            host_label=str(data.get("host_label", "App address")), client=data["client"],
            guide=str(data.get("guide", "")), notes=str(data.get("notes", "")),
            needs=str(data.get("needs", "")), main_config=str(data.get("main_config", "")),
        ))  # fmt: skip
    rank = {name: i for i, name in enumerate(ORDER)}
    return tuple(sorted(found, key=lambda t: (rank.get(t.id, len(ORDER)), t.name.lower())))


def get(template_id: str) -> Template | None:
    return next((t for t in load_all() if t.id == template_id), None)
