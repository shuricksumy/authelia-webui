"""The OIDC signing keys file (`managed/oidc_jwks.yml`) as text blocks, one per key.

The file only works through Authelia's template filter, because a key's private PEM is not in it:

    - key_id: 'abc'
      algorithm: 'RS256'
      use: 'sig'
      key: {{ secret "/config/managed/secrets/jwks/abc.pem" | mindent 10 "|" | msquote }}

so it is not valid YAML before templating and cannot go through a YAML parser. This module reads
and edits it as text, strictly: a file in any other shape is refused rather than rewritten. Private
key material never enters this module; it only knows file paths.

Order matters: Authelia signs with the first key of an algorithm and publishes all of them. A
rotation is therefore add (published, not signing) -> promote (move to the front) -> retire
(remove the old one); `Rotation` names which of these is possible for a file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from app.blocklist import ODD_LINE_BREAKS, DocumentError

JWKS_NAME = "oidc_jwks.yml"
SECRETS_SUBDIR = Path("secrets") / "jwks"
KID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
ITEM = re.compile(r"^      - ")
HEADER = (
    "# Managed by the Authelia Configurator: the OIDC signing keys (rotate on its Keys page).\n"
    "# The private keys are files in secrets/jwks/ (never in git); this file only names them and\n"
    "# needs X_AUTHELIA_CONFIG_FILTERS=template.\n"
)
_FIELD = r"^(?:      - |        )%s:\s*(.*?)\s*$"
_KEY_ID, _ALGORITHM, _USE = (re.compile(_FIELD % f) for f in ("key_id", "algorithm", "use"))
_KEY_FILE = re.compile(
    r'^        key:\s*\{\{\s*secret\s+"([^"]+)"\s*\|\s*mindent 10 "\|"\s*\|\s*msquote\s*\}\}\s*$'
)
_INLINE_KEY = re.compile(r"^(?:      - |        )key:")
_CHAIN = re.compile(r"^        certificate_chain:\s*[|>]")


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def key_path(managed_dir: Path, kid: str) -> Path:
    """Where the private key of `kid` lives (the path Authelia and this tool both see)."""
    if not KID.match(kid):
        raise DocumentError("key ids may use letters, digits, - and _ (max 64)")
    return managed_dir / SECRETS_SUBDIR / f"{kid}.pem"


@dataclass(frozen=True)
class KeyInfo:
    kid: str
    algorithm: str
    use: str
    secret_path: str  # "" when the key is inline in the file (not migrated)
    chain: str  # the PEM certificate chain, "" when none (public data)

    @property
    def inline(self) -> bool:
        return not self.secret_path


@dataclass(frozen=True)
class KeyBlock:
    entry: KeyInfo
    lines: tuple[str, ...]


@dataclass(frozen=True)
class JwksDocument:
    prefix: tuple[str, ...]
    blocks: tuple[KeyBlock, ...]
    suffix: tuple[str, ...]

    # ------------------------------------------------------------------ parse / render

    @classmethod
    def parse(cls, text: str) -> JwksDocument:
        if ODD_LINE_BREAKS.search(text):
            raise DocumentError("the keys file contains unusual line-break characters")
        lines = text.splitlines()
        starts_at = [i for i, ln in enumerate(lines) if ln.rstrip() == "    jwks:"]
        if len(starts_at) != 1:
            raise DocumentError("the keys file is not in the layout this tool writes")
        start = starts_at[0]
        starts = [i for i in range(start + 1, len(lines)) if ITEM.match(lines[i])]
        if not starts:
            raise DocumentError("the keys file lists no keys")
        end = len(lines)
        for i in range(starts[-1] + 1, len(lines)):
            line = lines[i]
            if (
                line.strip()
                and not line.startswith("        ")
                and not line.lstrip().startswith("#")
            ):
                end = i
                break
        while end > starts[-1] + 1 and not lines[end - 1].strip():
            end -= 1
        blocks = []
        for n, first in enumerate(starts):
            stop = starts[n + 1] if n + 1 < len(starts) else end
            chunk = lines[first:stop]
            while chunk and not chunk[-1].strip():
                chunk.pop()
            blocks.append(KeyBlock(_info(chunk), tuple(chunk)))
        doc = cls(tuple(lines[: starts[0]]), tuple(blocks), tuple(lines[end:]))
        kids = [b.entry.kid for b in doc.blocks]
        if len(set(kids)) != len(kids):
            raise DocumentError("two keys share a key_id")
        return doc

    def render(self) -> str:
        out = [*self.prefix]
        for block in self.blocks:
            out.extend(block.lines)
        out.extend(self.suffix)
        return "\n".join(out) + "\n"

    # ------------------------------------------------------------------ read

    def entries(self) -> list[KeyInfo]:
        return [b.entry for b in self.blocks]

    def kids(self) -> list[str]:
        return [b.entry.kid for b in self.blocks]

    def get(self, kid: str) -> KeyInfo:
        for block in self.blocks:
            if block.entry.kid == kid:
                return block.entry
        raise DocumentError(f"no key '{kid}'")

    # ------------------------------------------------------------------ edit (return new docs)

    def with_added(self, kid: str, algorithm: str, secret_path: Path) -> JwksDocument:
        if kid in self.kids():
            raise DocumentError(f"key '{kid}' already exists")
        lines = entry_lines(kid, algorithm, secret_path)
        block = KeyBlock(_info(list(lines)), lines)
        return replace(self, blocks=(*self.blocks, block))

    def promoted(self, kid: str) -> JwksDocument:
        self.get(kid)
        chosen = [b for b in self.blocks if b.entry.kid == kid]
        rest = [b for b in self.blocks if b.entry.kid != kid]
        return replace(self, blocks=(*chosen, *rest))

    def removed(self, kid: str) -> JwksDocument:
        self.get(kid)
        if len(self.blocks) == 1:
            raise DocumentError("the last key cannot be removed: Authelia needs one to sign")
        return replace(self, blocks=tuple(b for b in self.blocks if b.entry.kid != kid))


def entry_lines(kid: str, algorithm: str, secret_path: Path) -> tuple[str, ...]:
    if not KID.match(kid):
        raise DocumentError("key ids may use letters, digits, - and _ (max 64)")
    if not re.fullmatch(r"[A-Z]{2}\d{3}", algorithm):
        raise DocumentError("unexpected key algorithm")
    return (
        f"      - key_id: '{kid}'",
        f"        algorithm: '{algorithm}'",
        "        use: 'sig'",
        f'        key: {{{{ secret "{secret_path}" | mindent 10 "|" | msquote }}}}',
    )


def new_document(entries: list[tuple[str, ...]]) -> JwksDocument:
    prefix = (*HEADER.splitlines(), "identity_providers:", "  oidc:", "    jwks:")
    blocks = tuple(KeyBlock(_info(list(e)), e) for e in entries)
    return JwksDocument(prefix, blocks, ())


def _info(chunk: list[str]) -> KeyInfo:
    def field(pattern: re.Pattern[str]) -> str:
        for line in chunk:
            m = pattern.match(line)
            if m:
                return _unquote(m.group(1))
        return ""

    kid = field(_KEY_ID)
    if not KID.match(kid):
        raise DocumentError("a key in the keys file has no usable key_id")
    secret = ""
    for line in chunk:
        m = _KEY_FILE.match(line)
        if m:
            secret = m.group(1)
            break
    if not secret and not any(_INLINE_KEY.match(line) for line in chunk):
        raise DocumentError(f"key '{kid}' has no key")
    chain: list[str] = []
    take = False
    for line in chunk:
        if _CHAIN.match(line):
            take = True
            continue
        if take:
            if line.startswith("          "):
                chain.append(line.strip())
            else:
                take = False
    return KeyInfo(kid, field(_ALGORITHM), field(_USE) or "sig", secret, "\n".join(chain))


def main_config_has_jwks(main_config: Path) -> bool:
    """Whether the main config still lists signing keys (a yes/no; nothing else is read)."""
    try:
        data = YAML(typ="safe", pure=True).load(main_config.read_text())
    except (OSError, YAMLError):
        return False
    oidc = ((data or {}).get("identity_providers") or {}).get("oidc") or {}
    return bool(oidc.get("jwks"))
