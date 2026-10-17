"""What the main config says about users: declared extra attributes, the password policy and
whether users log in by email. Only these settings are read; nothing else leaves this module."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

VALUE_TYPES = ("string", "integer", "boolean")


@dataclass(frozen=True)
class ExtraAttribute:
    name: str
    value_type: str = "string"
    multi_valued: bool = False


@dataclass(frozen=True)
class PasswordPolicy:
    mode: str = "none"  # none | standard | zxcvbn
    min_length: int = 8
    max_length: int = 0  # 0 = no maximum
    require_uppercase: bool = False
    require_lowercase: bool = False
    require_number: bool = False
    require_special: bool = False
    min_score: int = 3  # zxcvbn


@dataclass(frozen=True)
class UsersSchema:
    extra: dict[str, ExtraAttribute] = field(default_factory=dict)
    policy: PasswordPolicy = field(default_factory=PasswordPolicy)
    login_by_email: bool = False
    watch: bool = False
    path: str = ""


def _get(data: Any, *keys: str) -> Any:
    for key in keys:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def load_schema(main_config: Path) -> UsersSchema:
    try:
        data = YAML(typ="safe", pure=True).load(main_config.read_text())
    except (OSError, YAMLError):
        return UsersSchema()
    file_backend = _get(data, "authentication_backend", "file") or {}
    extra = {}
    for name, spec in (_get(file_backend, "extra_attributes") or {}).items():
        spec = spec if isinstance(spec, dict) else {}
        value_type = str(spec.get("value_type") or "string")
        extra[str(name)] = ExtraAttribute(
            str(name), value_type if value_type in VALUE_TYPES else "string",
            bool(spec.get("multi_valued")),
        )  # fmt: skip
    policy = PasswordPolicy()
    standard = _get(data, "password_policy", "standard") or {}
    zxcvbn = _get(data, "password_policy", "zxcvbn") or {}
    if isinstance(standard, dict) and standard.get("enabled"):
        policy = PasswordPolicy(
            mode="standard",
            min_length=int(standard.get("min_length") or 8),
            max_length=int(standard.get("max_length") or 0),
            require_uppercase=bool(standard.get("require_uppercase")),
            require_lowercase=bool(standard.get("require_lowercase")),
            require_number=bool(standard.get("require_number")),
            require_special=bool(standard.get("require_special")),
        )
    elif isinstance(zxcvbn, dict) and zxcvbn.get("enabled"):
        policy = PasswordPolicy(mode="zxcvbn", min_score=int(zxcvbn.get("min_score") or 3))
    return UsersSchema(
        extra=extra,
        policy=policy,
        login_by_email=bool(_get(file_backend, "search", "email")),
        watch=bool(file_backend.get("watch")) if isinstance(file_backend, dict) else False,
        path=str(file_backend.get("path") or "") if isinstance(file_backend, dict) else "",
    )


def policy_problems(password: str, policy: PasswordPolicy) -> list[str]:
    """Plain-language reasons why `password` does not meet the standard policy."""
    out = []
    if policy.mode == "zxcvbn":
        return ["Your password policy uses zxcvbn, which cannot be checked here; generate one."]
    minimum = max(policy.min_length, 8) if policy.mode == "standard" else 8
    if len(password) < minimum:
        out.append(f"at least {minimum} characters")
    if policy.max_length and len(password) > policy.max_length:
        out.append(f"at most {policy.max_length} characters")
    if policy.require_uppercase and not any(c.isupper() for c in password):
        out.append("an uppercase letter")
    if policy.require_lowercase and not any(c.islower() for c in password):
        out.append("a lowercase letter")
    if policy.require_number and not any(c.isdigit() for c in password):
        out.append("a number")
    if policy.require_special and all(c.isalnum() for c in password):
        out.append("a special character")
    return out
