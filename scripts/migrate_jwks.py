"""One-time move of the OIDC signing keys out of the main Authelia config (Phase 4c).

    python -m scripts.migrate_jwks --config /path/configuration.yml --managed /path/managed \
        [--container-managed /config/managed] [--reduced-main /path/configuration.reduced.yml]

What it does:
- writes each key's private PEM to <managed>/secrets/jwks/<key_id>.pem (mode 600, folder 700);
- writes <managed>/oidc_jwks.yml, which names those files through Authelia's template filter;
- with --reduced-main, writes a copy of the main config without its `jwks:` list.

The main configuration itself is never modified, and nothing is overwritten: you diff the reduced
copy, move it into place yourself, and add the new file to X_AUTHELIA_CONFIG together with
X_AUTHELIA_CONFIG_FILTERS=template (see docs/jwks.md). No key material is printed.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from app.oidc.jwks import (
    JWKS_NAME,
    KID,
    SECRETS_SUBDIR,
    JwksDocument,
    entry_lines,
    new_document,
)

KNOWN_FIELDS = {"key_id", "algorithm", "use", "key", "certificate_chain"}


class MigrationError(RuntimeError):
    """The move cannot proceed; the message is safe to print (no key material)."""


@dataclass(frozen=True)
class Migration:
    kids: list[str]
    generated_kids: list[str]  # key ids this script had to invent (they change what apps see)
    keys_file: str  # text of oidc_jwks.yml
    private_keys: dict[str, str]  # kid -> PEM text (written by the caller, never printed)


def read_keys(main_text: str) -> list[dict[str, Any]]:
    try:
        data = YAML(typ="safe", pure=True).load(main_text)
    except YAMLError:
        raise MigrationError("the main configuration is not valid YAML") from None
    oidc = ((data or {}).get("identity_providers") or {}).get("oidc") or {}
    keys = oidc.get("jwks")
    if not isinstance(keys, list) or not keys:
        raise MigrationError("the main configuration lists no OIDC signing keys (jwks)")
    return keys


def plan(main_text: str, container_managed: Path) -> Migration:
    keys = read_keys(main_text)
    entries: list[tuple[str, ...]] = []
    chains: dict[str, str] = {}
    private: dict[str, str] = {}
    kids: list[str] = []
    generated: list[str] = []
    for n, key in enumerate(keys, 1):
        if not isinstance(key, dict) or not isinstance(key.get("key"), str):
            raise MigrationError(f"signing key {n} has no inline 'key' to move")
        extra = set(key) - KNOWN_FIELDS
        if extra:
            raise MigrationError(f"signing key {n} has fields this tool does not move: "
                                 + ", ".join(sorted(map(str, extra))))  # fmt: skip
        kid = str(key.get("key_id") or f"key-{n}")
        if not key.get("key_id"):
            generated.append(kid)
        if not KID.match(kid):
            raise MigrationError(f"signing key {n}: the key_id is not usable as a file name")
        if kid in kids:
            raise MigrationError(f"two signing keys share the key_id '{kid}'")
        kids.append(kid)
        private[kid] = key["key"].strip() + "\n"
        path = container_managed / SECRETS_SUBDIR / f"{kid}.pem"
        entries.append(entry_lines(kid, str(key.get("algorithm") or "RS256"), path))
        if isinstance(key.get("certificate_chain"), str) and key["certificate_chain"].strip():
            chains[kid] = key["certificate_chain"].strip()
    doc = new_document(entries)
    text = doc.render()
    for kid, chain in chains.items():  # public data: copied verbatim under its key
        marker = f'secrets/jwks/{kid}.pem" | mindent 10 "|" | msquote }}}}\n'
        block = "        certificate_chain: |\n" + "".join(
            f"          {line}\n" for line in chain.splitlines()
        )
        if marker not in text:
            raise MigrationError("internal error placing a certificate chain")
        text = text.replace(marker, marker + block, 1)
    JwksDocument.parse(text)  # what we wrote must be what the tool can read back
    return Migration(kids, generated, text, private)


def without_jwks(main_text: str) -> str:
    """The main config text minus its `jwks:` list (every other line untouched)."""
    lines = main_text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)jwks:\s*(#.*)?$", line)
        if m:
            indent = len(m.group(1))
            end = i + 1
            while end < len(lines) and (
                not lines[end].strip() or len(lines[end]) - len(lines[end].lstrip()) > indent
            ):
                end += 1
            while end > i + 1 and not lines[end - 1].strip():
                end -= 1  # keep the blank line(s) before the next key
            return "\n".join(lines[:i] + lines[end:]) + "\n"
    raise MigrationError("no 'jwks:' list found in the main configuration")


def _write_private(path: Path, text: str) -> None:
    """Write a new file (mode 600). Folders it creates are 700; existing ones are left alone
    (the managed folder and Authelia's folder belong to the deployment)."""
    missing = [p for p in (path.parent, *path.parent.parents) if not p.exists()]
    for folder in reversed(missing):
        folder.mkdir(mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(text)


def write(migration: Migration, managed: Path) -> list[Path]:
    keys_file = managed / JWKS_NAME
    targets = [managed / SECRETS_SUBDIR / f"{k}.pem" for k in migration.kids]
    for path in [keys_file, *targets]:
        if path.exists():
            raise MigrationError(f"{path} already exists; nothing was written")
    written = []
    for kid, path in zip(migration.kids, targets, strict=True):
        _write_private(path, migration.private_keys[kid])
        written.append(path)
    (managed / SECRETS_SUBDIR.parent).mkdir(mode=0o700, exist_ok=True)
    _write_private(keys_file, migration.keys_file)
    keys_file.chmod(0o600)
    return [keys_file, *written]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--managed", type=Path, required=True)
    parser.add_argument(
        "--container-managed", type=Path, default=Path("/config/managed"),
        help="where Authelia sees the managed folder (default /config/managed)",
    )  # fmt: skip
    parser.add_argument(
        "--reduced-main", type=Path,
        help="write a copy of the main config without its jwks list here",
    )  # fmt: skip
    args = parser.parse_args(argv)
    try:
        text = args.config.read_text()
        migration = plan(text, args.container_managed)
        reduced = without_jwks(text) if args.reduced_main else None
        if args.reduced_main and args.reduced_main.exists():
            raise MigrationError(f"{args.reduced_main} already exists; nothing was written")
        written = write(migration, args.managed)
        if args.reduced_main and reduced is not None:
            _write_private(args.reduced_main, reduced)
    except (MigrationError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"moved {len(migration.kids)} signing key(s): {', '.join(migration.kids)}")
    for path in written:
        print(f"  wrote {path}")
    if migration.generated_kids:
        names = ", ".join(migration.generated_kids)
        print(f"note: no key_id was set for {names}; ids were invented, so apps will see a "
              "different 'kid' after the switch.")  # fmt: skip
    print("\nNext (the main file was not touched):")
    print(f"  1. add {args.container_managed}/{JWKS_NAME} to the end of X_AUTHELIA_CONFIG")
    print("  2. set X_AUTHELIA_CONFIG_FILTERS=template (Authelia) and "
          "CONFIG_FILTERS=template (configurator), restart both")  # fmt: skip
    copy = f" ({args.reduced_main} is a copy without it)" if args.reduced_main else ""
    print("  optional, later: remove the `jwks:` list from the main configuration; the managed "
          f"file already replaces it{copy}")  # fmt: skip
    return 0


if __name__ == "__main__":
    sys.exit(main())
