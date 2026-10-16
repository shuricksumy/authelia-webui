"""Disabled rules (SPEC §16.1): exact round trip, migration format, two-file draft and apply."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from app.rules.disabled import DisabledRules
from app.rules.document import DocumentError, RulesDocument
from app.rules.store import DraftStore, summarise
from tests.unit.test_apply import env as apply_env  # noqa: F401  (fixture)
from tests.unit.test_apply import git, live, make, run
from tests.unit.test_rules_document import SIMPLE


def test_disable_then_enable_is_byte_identical() -> None:
    doc = RulesDocument.parse(SIMPLE)
    for index in range(len(doc.blocks)):
        disabled = DisabledRules().add(index, doc.blocks[index])
        stored = DisabledRules.parse(disabled.render())  # through the file format
        entry = stored.entries[0]
        assert entry.position == index
        back = doc.delete(index).insert_block(entry.position, entry.block)
        assert back.render() == SIMPLE, index


def test_note_and_inner_comments_are_kept_in_the_file() -> None:
    doc = RulesDocument.parse(SIMPLE)
    text = DisabledRules().add(0, doc.blocks[0]).render()
    assert "# first rule note" in text and "commented-out" in text and "# inline note" in text
    assert "..." not in text  # no document-end marker from trailing blank lines


def test_migration_script_format_is_read() -> None:
    text = (
        "# Rules disabled in the configurator; never passed to Authelia.\n"
        "disabled_rules:\n  - position: 2\n    rule:\n      domain: a.example.com\n"
        "      policy: bypass\n"
    )
    entry = DisabledRules.parse(text).entries[0]
    assert entry.position == 2 and entry.data() == {"domain": "a.example.com", "policy": "bypass"}
    doc = RulesDocument.parse(SIMPLE).insert_block(entry.position, entry.block)
    assert doc.rules()[2] == {"domain": "a.example.com", "policy": "bypass"}


@pytest.mark.parametrize(
    "text",
    ["disabled_rules: [unclosed", "disabled_rules: 3\n", "disabled_rules:\n  - just-text\n",
     "disabled_rules:\n  - position: 1\n"],
)  # fmt: skip
def test_invalid_files_are_refused(text: str) -> None:
    with pytest.raises(DocumentError):
        DisabledRules.parse(text)


def test_empty_renders_nothing_and_enable_position_is_clamped() -> None:
    assert DisabledRules().render() == ""
    doc = RulesDocument.parse(SIMPLE)
    far = DisabledRules().add(99, doc.blocks[0]).entries[0]
    assert (
        doc.delete(0).insert_block(far.position, far.block).rules()[-1]["domain"] == "a.example.com"
    )


def test_change_summary_counts_disable_and_enable_not_add_and_remove() -> None:
    doc = RulesDocument.parse(SIMPLE)
    disabled = DisabledRules().add(1, doc.blocks[1])
    summary = summarise(doc, doc.delete(1), DisabledRules(), disabled)
    assert (summary.disabled, summary.removed, summary.added) == (1, 0, 0)
    back = summarise(doc.delete(1), doc, disabled, DisabledRules())
    assert (back.enabled, back.added, back.removed) == (1, 0, 0)
    gone = summarise(doc, doc, disabled, DisabledRules())
    assert gone.deleted_disabled == 1 and gone.any


def test_two_file_draft_revision_and_staleness(tmp_path: Path) -> None:
    (tmp_path / "access_control.yml").write_text(SIMPLE)
    store = DraftStore(tmp_path)
    before = store.current_sha()
    doc = store.current()
    store.save(doc.delete(2), expected_sha=before, disabled=DisabledRules().add(2, doc.blocks[2]))
    assert store.has_draft() and store.current_sha() != before
    assert store.current_disabled().entries[0].position == 2
    assert not (tmp_path / "disabled_rules.yml").exists()  # live untouched
    assert "disabled_rules.yml (draft)" in store.diff()
    assert store.changes().disabled == 1
    (tmp_path / "disabled_rules.yml").write_text("disabled_rules: []\n")  # changed by hand
    assert store.is_stale()


def test_restoring_both_files_to_live_removes_the_draft(tmp_path: Path) -> None:
    (tmp_path / "access_control.yml").write_text(SIMPLE)
    store = DraftStore(tmp_path)
    doc = store.current()
    store.save(doc.delete(2), disabled=DisabledRules().add(2, doc.blocks[2]))
    entry = store.current_disabled().entries[0]
    store.save(store.current().insert_block(entry.position, entry.block), disabled=DisabledRules())
    assert not store.has_draft()


def _disable_rule(env: dict[str, Any], index: int) -> str:
    store: DraftStore = env["store"]
    doc = store.current()
    store.save(doc.delete(index), disabled=DisabledRules().add(index, doc.blocks[index]))
    return store.current_sha()[:16]


def test_apply_writes_both_files_in_one_commit(apply_env: dict[str, Any]) -> None:  # noqa: F811
    rev = _disable_rule(apply_env, 4)  # the photos 2FA rule (not protected)
    engine, _, _ = make(apply_env, [True])
    job = run(engine, rev)
    assert job.result == "applied", job.message
    managed = apply_env["managed"]
    assert "photos.example.com" in (managed / "disabled_rules.yml").read_text()
    files = git(managed, "show", "--name-only", "--format=", "HEAD").split()
    assert sorted(files) == ["access_control.yml", "disabled_rules.yml"]
    assert git(managed, "log", "--format=%s", "-n1").strip() == "Rules: 1 disabled"
    assert git(managed, "status", "--porcelain").strip() == ""


def test_rollback_restores_both_files_and_both_drafts(apply_env: dict[str, Any]) -> None:  # noqa: F811
    original = live(apply_env)
    rev = _disable_rule(apply_env, 4)
    engine, _, _ = make(apply_env, [False, True])
    job = run(engine, rev)
    assert job.result == "rolled-back"
    managed = apply_env["managed"]
    assert live(apply_env) == original and not (managed / "disabled_rules.yml").exists()
    store: DraftStore = apply_env["store"]
    assert store.has_draft() and len(store.current_disabled().entries) == 1


def test_protected_rules_cannot_be_disabled(apply_env: dict[str, Any]) -> None:  # noqa: F811
    """Disabling = removing from the rules Authelia sees, so the behavioural check refuses it."""
    rev = _disable_rule(apply_env, 2)  # the explicit deny for the configurator
    engine, _, _ = make(apply_env, [True])
    job = run(engine, rev)
    assert job.result == "refused" and "Protected rules" in job.message


def test_disable_enable_survives_saving_and_reparsing_every_rule(tmp_path: Path) -> None:
    """Through the real draft files (save -> re-parse) for every position, incl. the last."""
    for index in range(3):
        (tmp_path / "access_control.yml").write_text(SIMPLE)
        store = DraftStore(tmp_path)
        doc = store.current()
        store.save(doc.delete(index), disabled=DisabledRules().add(index, doc.blocks[index]))
        entry = store.current_disabled().entries[0]
        store.save(
            store.current().insert_block(entry.position, entry.block), disabled=DisabledRules()
        )
        assert not store.has_draft(), index  # identical to live again
