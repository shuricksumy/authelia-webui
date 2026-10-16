"""The managed oidc_clients.yml (identity_providers.oidc.clients) as text blocks.

Untouched clients stay byte-identical (app/blocklist.py). The client secret is only ever a
hash here: rotating it replaces just the `client_secret` line, so nothing else in the client
is re-serialised.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ruamel.yaml.scalarstring import SingleQuotedScalarString

from app.blocklist import Block, BlockList, DocumentError, locate

CLIENTS_NAME = "oidc_clients.yml"
PATH = ("identity_providers", "oidc", "clients")
EMPTY = "identity_providers:\n  oidc:\n    clients: []\n"
# A digest as printed by `authelia crypto hash generate`: no quotes, spaces or newlines.
DIGEST = re.compile(r"^\$[a-z0-9-]+\$[A-Za-z0-9$./+=,_-]+$")
SECRET_LINE = re.compile(r"^(\s*(?:- )?)client_secret(\s*):(\s*)(\S.*)?$")


def secret_kind(value: Any) -> str:
    """'' (none), 'pbkdf2', 'argon2', 'bcrypt', 'scrypt', 'sha2crypt', 'plaintext' or 'other'."""
    if value is None or value == "":
        return ""
    text = str(value)
    if text.startswith("$plaintext$") or not text.startswith("$"):
        return "plaintext"
    for kind in ("pbkdf2", "argon2", "bcrypt", "scrypt"):
        if text.startswith(f"${kind}"):
            return kind
    if text.startswith(("$2a$", "$2b$", "$2y$")):
        return "bcrypt"
    if text.startswith(("$5$", "$6$")):
        return "sha2crypt"
    return "other"


@dataclass(frozen=True)
class ClientsDocument(BlockList):
    LIST_KEY = "clients"

    @classmethod
    def parse(cls, text: str) -> ClientsDocument:
        loc, clients = locate(text, PATH, CLIENTS_NAME)
        prefix, blocks, suffix = cls.cut(loc, clients, ".".join(PATH))
        return cls(prefix, blocks, suffix)

    def clients(self) -> list[dict[str, Any]]:
        return self.items()

    def client_ids(self) -> list[str]:
        return [str(c.get("client_id", "")) for c in self.clients()]

    def index_of(self, client_id: str) -> int | None:
        ids = self.client_ids()
        return ids.index(client_id) if ids.count(client_id) == 1 else None

    def with_secret(self, index: int, digest: str) -> ClientsDocument:
        """Set the client's secret hash. Only the `client_secret` line changes when it exists."""
        if not DIGEST.match(digest):
            raise DocumentError("refusing to store something that is not a password hash")
        self._check(index)
        block = self.blocks[index]
        start, dash = block.rule_start, block.dash_col
        hits = []
        for i in range(start, len(block.lines)):
            m = SECRET_LINE.match(block.lines[i])
            if not m:
                continue
            indent = len(m.group(1))  # "- " on the dash line counts as indentation
            if indent == dash + 2:
                hits.append((i, m))
        value = hits[0][1].group(4) if len(hits) == 1 else None
        if value and not value.startswith(("|", ">", "&", "*", "!")):
            i, m = hits[0]
            comment = value[value.index(" #") :] if " #" in value else ""  # hashes hold no '#'
            lines = list(block.lines)
            lines[i] = (
                f"{m.group(1)}client_secret{m.group(2)}:{m.group(3) or ' '}'{digest}'{comment}"
            )
            candidate = Block(tuple(lines))
            expected = {**block.data(), "client_secret": digest}
            try:
                same = candidate.data() == expected
            except DocumentError:
                same = False
            if same:  # e.g. a quoted plaintext secret holding " #" would not survive this
                blocks = list(self.blocks)
                blocks[index] = candidate
                return self._with(blocks)
        node = block.node()  # absent, or written in an unusual way: re-serialise this client
        node["client_secret"] = SingleQuotedScalarString(digest)
        return self.replace_item(index, node)

    def _with(self, blocks: list[Block]) -> ClientsDocument:
        return ClientsDocument(self.prefix, tuple(blocks), self.suffix)


@dataclass(frozen=True)
class ClientChanges:
    added: int = 0
    removed: int = 0
    edited: int = 0
    secrets_rotated: int = 0  # among the edited (or a secret added to a kept client)


def summarise_clients(live: ClientsDocument | None, draft: ClientsDocument | None) -> ClientChanges:
    """Compare by client_id; a client whose block text changed counts as edited."""
    if live is None or draft is None:
        return ClientChanges()

    def by_id(doc: ClientsDocument) -> dict[str, tuple[tuple[str, ...], Any]]:
        out = {}
        for block in doc.blocks:
            try:
                data = block.data()
            except DocumentError:
                continue
            out[str(data.get("client_id", ""))] = (block.lines, data.get("client_secret"))
        return out

    old, new = by_id(live), by_id(draft)
    edited = rotated = 0
    for cid in old.keys() & new.keys():
        if _strip(old[cid][0]) != _strip(new[cid][0]):
            edited += 1
            if old[cid][1] != new[cid][1] and new[cid][1]:
                rotated += 1
    return ClientChanges(
        added=len(new.keys() - old.keys()),
        removed=len(old.keys() - new.keys()),
        edited=edited,
        secrets_rotated=rotated,
    )


def _strip(lines: tuple[str, ...]) -> tuple[str, ...]:
    out = list(lines)
    while out and not out[-1].strip():
        out.pop()
    return tuple(out)
