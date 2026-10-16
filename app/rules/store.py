"""Live files, draft and users file (SPEC §4, §5, §6, §9 read-only part).

The live files are CONFIG_MANAGED_DIR/{access_control,disabled_rules,oidc_clients}.yml. Only
the apply engine writes them: edits go to one shared draft in CONFIG_MANAGED_DIR/.draft/, which
is always a full snapshot of all three (so the rules draft file doubles as "a draft exists").
`meta.json` remembers the hash of each live file the draft started from, so a draft that no
longer matches them is reported as stale (apply refuses stale drafts).
"""

from __future__ import annotations

import contextlib
import difflib
import fcntl
import hashlib
import json
import os
import tempfile
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from app.authelia_cli import redact
from app.oidc.document import CLIENTS_NAME, ClientChanges, ClientsDocument, summarise_clients
from app.rules.disabled import DISABLED_NAME, DisabledRules
from app.rules.document import DocumentError, RulesDocument
from app.rules.lint import UsersInfo

LIVE_NAME = "access_control.yml"


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def load_users(path: Path) -> UsersInfo:
    """Usernames and group names only. Password hashes are never kept: they are dropped
    inside this function and no other field is read."""
    try:
        data = YAML(typ="safe", pure=True).load(path.read_text())
    except (OSError, YAMLError):
        return UsersInfo(frozenset(), frozenset(), available=False)
    users = (data or {}).get("users") or {}
    names: set[str] = set()
    groups: set[str] = set()
    memberships: dict[str, tuple[str, ...]] = {}
    for name, fields in users.items():
        names.add(str(name))
        own = tuple(str(g) for g in (fields or {}).get("groups") or [])
        memberships[str(name)] = own
        groups.update(own)
    return UsersInfo(frozenset(names), frozenset(groups), memberships=memberships)


def load_main_definitions(path: Path) -> dict[str, Any]:
    """Only `definitions` (named networks) from the read-only main config; nothing else is read
    into memory beyond the parsed tree, which is discarded here."""
    try:
        data = YAML(typ="safe", pure=True).load(path.read_text())
    except (OSError, YAMLError):
        return {}
    definitions = (data or {}).get("definitions")
    return {"definitions": definitions} if isinstance(definitions, dict) else {}


def state_sha(doc: RulesDocument, disabled: DisabledRules, clients_text: str = "") -> str:
    """Revision of a draft state: every file, so any edit to any of them changes it."""
    return sha256(doc.render() + "\0" + disabled.render() + "\0" + clients_text)


@dataclass(frozen=True)
class Snapshot:
    """The text of every drafted file. `clients` is "" when there is no oidc_clients.yml."""

    rules: str
    disabled: str
    clients: str


@dataclass(frozen=True)
class ChangeSummary:
    added: int
    removed: int
    edited: int
    order_changed: bool
    default_policy_changed: bool
    disabled: int = 0
    enabled: int = 0
    deleted_disabled: int = 0
    clients: ClientChanges = field(default_factory=ClientChanges)

    @property
    def rules_count(self) -> int:
        return (
            self.added + self.removed + self.edited + self.disabled + self.enabled
            + self.deleted_disabled + int(self.order_changed) + int(self.default_policy_changed)
        )  # fmt: skip

    @property
    def count(self) -> int:
        c = self.clients
        return self.rules_count + c.added + c.removed + c.edited

    @property
    def any(self) -> bool:
        return self.count > 0


def _stripped(lines: tuple[str, ...]) -> tuple[str, ...]:
    out = list(lines)
    while out and not out[-1].strip():
        out.pop()
    return tuple(out)


def summarise(
    live: RulesDocument,
    draft: RulesDocument,
    live_disabled: DisabledRules | None = None,
    draft_disabled: DisabledRules | None = None,
) -> ChangeSummary:
    live_disabled = live_disabled or DisabledRules()
    draft_disabled = draft_disabled or DisabledRules()
    newly_disabled = Counter(e.lines for e in draft_disabled.entries) - Counter(
        e.lines for e in live_disabled.entries
    )
    newly_enabled = Counter(e.lines for e in live_disabled.entries) - Counter(
        e.lines for e in draft_disabled.entries
    )
    live_blocks = Counter(b.lines for b in live.blocks)
    draft_blocks = Counter(b.lines for b in draft.blocks)
    gone = list((live_blocks - draft_blocks).elements())
    new = list((draft_blocks - live_blocks).elements())
    # A rule that moved into the disabled list is "disabled", not "removed" (and vice versa).
    disabled = enabled = 0
    for lines in list(gone):
        if newly_disabled[_stripped(lines)] > 0:
            newly_disabled[_stripped(lines)] -= 1
            gone.remove(lines)
            disabled += 1
    for lines in list(new):
        if newly_enabled[_stripped(lines)] > 0:
            newly_enabled[_stripped(lines)] -= 1
            new.remove(lines)
            enabled += 1
    deleted_disabled = sum(newly_enabled.values())  # left the disabled list, not re-enabled

    def domain(lines: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(_safe_domain(lines)))

    edited = 0
    pool = [domain(lines) for lines in gone]
    for lines in new:
        key = domain(lines)
        if key in pool:
            pool.remove(key)
            edited += 1
    remaining = [b.lines for b in draft.blocks if b.lines in live_blocks]
    original = [b.lines for b in live.blocks if b.lines in draft_blocks]
    order_changed = not gone and not new and remaining != original
    return ChangeSummary(
        added=len(new) - edited,
        removed=len(gone) - edited,
        edited=edited,
        order_changed=order_changed,
        default_policy_changed=live.default_policy() != draft.default_policy(),
        disabled=disabled,
        enabled=enabled,
        deleted_disabled=deleted_disabled,
    )


def _safe_domain(lines: tuple[str, ...]) -> list[str]:
    from app.rules.document import RuleBlock
    from app.rules.tester import as_list

    try:
        return [str(d) for d in as_list(RuleBlock(lines).data().get("domain"))]
    except DocumentError:
        return []


class StaleDraftError(RuntimeError):
    """The draft (or live file) changed after the caller read it."""


class DraftStore:
    def __init__(self, managed_dir: Path) -> None:
        self.managed_dir = managed_dir
        self.live_path = managed_dir / LIVE_NAME
        self.draft_dir = managed_dir / ".draft"
        self.draft_path = self.draft_dir / LIVE_NAME
        self.disabled_live_path = managed_dir / DISABLED_NAME
        self.disabled_draft_path = self.draft_dir / DISABLED_NAME
        self.clients_live_path = managed_dir / CLIENTS_NAME
        self.clients_draft_path = self.draft_dir / CLIENTS_NAME
        self.meta_path = self.draft_dir / "meta.json"

    # ------------------------------------------------------------------ reading

    def live_text(self) -> str:
        return self.live_path.read_text()

    def live(self) -> RulesDocument:
        return RulesDocument.parse(self.live_text())

    def live_disabled_text(self) -> str:
        try:
            return self.disabled_live_path.read_text()
        except FileNotFoundError:
            return ""

    def live_disabled(self) -> DisabledRules:
        return DisabledRules.parse(self.live_disabled_text())

    def has_draft(self) -> bool:
        return self.draft_path.is_file()

    def current(self) -> RulesDocument:
        """The draft when one exists, else the live file."""
        return RulesDocument.parse(
            self.draft_path.read_text() if self.has_draft() else self.live_text()
        )

    def current_disabled(self) -> DisabledRules:
        if self.has_draft() and self.disabled_draft_path.is_file():
            return DisabledRules.parse(self.disabled_draft_path.read_text())
        return self.live_disabled()

    def live_clients_text(self) -> str:
        try:
            return self.clients_live_path.read_text()
        except FileNotFoundError:
            return ""

    def current_clients_text(self) -> str:
        if self.has_draft() and self.clients_draft_path.is_file():
            return self.clients_draft_path.read_text()
        return self.live_clients_text()

    def current_clients(self) -> ClientsDocument | None:
        """None when this deployment has no oidc_clients.yml (no OIDC provider)."""
        text = self.current_clients_text()
        return ClientsDocument.parse(text) if text else None

    def live_clients(self) -> ClientsDocument | None:
        text = self.live_clients_text()
        return ClientsDocument.parse(text) if text else None

    def snapshot(self) -> Snapshot:
        return Snapshot(
            self.current().render(), self.current_disabled().render(), self.current_clients_text()
        )

    def _bases(self) -> dict[str, str]:
        return {
            "base_sha256": sha256(self.live_text()),
            "base_disabled_sha256": sha256(self.live_disabled_text()),
            "base_clients_sha256": sha256(self.live_clients_text()),
        }

    def is_stale(self) -> bool:
        if not self.has_draft():
            return False
        try:
            meta = json.loads(self.meta_path.read_text())
        except (OSError, ValueError):
            return True
        bases = self._bases()
        if meta.get("base_sha256") != bases["base_sha256"]:
            return True
        # older drafts did not record every file: only compare what was recorded
        for key in ("base_disabled_sha256", "base_clients_sha256"):
            recorded = meta.get(key)
            if recorded is not None and recorded != bases[key]:
                return True
        return False

    def changes(self) -> ChangeSummary:
        rules = summarise(
            self.live(), self.current(), self.live_disabled(), self.current_disabled()
        )
        clients = summarise_clients(self.live_clients(), self.current_clients())
        return replace(rules, clients=clients)

    def diff(self) -> str:
        parts = []
        for name, live, draft in (
            (LIVE_NAME, self.live_text(), self.current().render()),
            (DISABLED_NAME, self.live_disabled_text(), self.current_disabled().render()),
            (CLIENTS_NAME, self.live_clients_text(), self.current_clients_text()),
        ):
            parts.append("".join(difflib.unified_diff(
                live.splitlines(keepends=True), draft.splitlines(keepends=True),
                f"{name} (live)", f"{name} (draft)",
            )))  # fmt: skip
        return redact("".join(parts))  # client secret hashes never reach a page

    # ------------------------------------------------------------------ writing the draft only

    def current_sha(self) -> str:
        return state_sha(self.current(), self.current_disabled(), self.current_clients_text())

    def locked(self) -> contextlib.AbstractContextManager[None]:
        """Hold the draft lock (used by apply while it writes the live file)."""
        return self._locked()

    def discard_unlocked(self) -> None:
        """Remove the draft; caller must hold `locked()`."""
        self._discard_unlocked()

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        """Exclusive lock for read-compare-write (several requests, threads or workers)."""
        self.draft_dir.mkdir(mode=0o700, exist_ok=True)
        with open(self.draft_dir / ".lock", "w") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def save(
        self,
        doc: RulesDocument,
        expected_sha: str | None = None,
        disabled: DisabledRules | None = None,
        clients: ClientsDocument | None = None,
    ) -> None:
        """Persist `doc` (and `disabled` / `clients`, default: unchanged) as the draft. A draft
        identical to the live files is removed.

        With `expected_sha` (state_sha of what the edit was based on) the write only happens if
        nothing changed in between; otherwise StaleDraftError (no lost updates).
        """
        with self._locked():
            if expected_sha is not None and self.current_sha() != expected_sha:
                raise StaleDraftError("the draft changed while this edit was being made")
            disabled = disabled if disabled is not None else self.current_disabled()
            clients_text = clients.render() if clients is not None else self.current_clients_text()
            if clients is not None and not self.live_clients_text():
                raise DocumentError("this deployment has no oidc_clients.yml")
            self._write_unlocked(Snapshot(doc.render(), disabled.render(), clients_text))

    def save_snapshot(self, snap: Snapshot, expected_sha: str | None = None) -> None:
        """Put a whole state in the draft (after a rollback, or "revert to this version")."""
        with self._locked():
            if expected_sha is not None and self.current_sha() != expected_sha:
                raise StaleDraftError("the draft changed while this edit was being made")
            self._write_unlocked(snap)

    def _write_unlocked(self, snap: Snapshot) -> None:
        live = (self.live_text(), self.live_disabled_text(), self.live_clients_text())
        if (snap.rules, snap.disabled, snap.clients) == live:
            self._discard_unlocked()
            return
        if not self.has_draft() or not self.meta_path.exists():
            self._atomic(self.meta_path, json.dumps(self._bases()))
        self._atomic(self.disabled_draft_path, snap.disabled)
        if snap.clients:
            self._atomic(self.clients_draft_path, snap.clients)
        else:
            self.clients_draft_path.unlink(missing_ok=True)
        self._atomic(self.draft_path, snap.rules)  # last: its presence means "a draft exists"

    def discard(self, expected_sha: str | None = None) -> None:
        with self._locked():
            if expected_sha is not None and self.current_sha() != expected_sha:
                raise StaleDraftError("the draft changed")
            self._discard_unlocked()

    def _discard_unlocked(self) -> None:
        for path in (self.draft_path, self.disabled_draft_path, self.clients_draft_path,
                     self.meta_path):  # fmt: skip
            path.unlink(missing_ok=True)

    def _atomic(self, path: Path, content: str) -> None:
        fd, tmp = tempfile.mkstemp(dir=self.draft_dir, prefix=".tmp-")
        try:
            with os.fdopen(fd, "w") as handle:
                handle.write(content)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
