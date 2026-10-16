from __future__ import annotations

import stat
from pathlib import Path

import pytest

from app.rules.document import RulesDocument
from app.rules.form import RuleForm, apply_form
from app.rules.store import DraftStore, load_main_definitions, load_users, summarise

LIVE = """access_control:
  default_policy: deny

  rules:
    - domain: a.example.com
      policy: bypass
      resources:
        - '^/x$'

    - domain: b.example.com
      policy: two_factor

    - domain: c.example.com
      policy: deny
"""


@pytest.fixture
def store(tmp_path: Path) -> DraftStore:
    (tmp_path / "access_control.yml").write_text(LIVE)
    return DraftStore(tmp_path)


def test_no_draft_means_current_is_live(store: DraftStore) -> None:
    assert not store.has_draft() and not store.is_stale()
    assert store.current().render() == LIVE
    assert not store.changes().any and store.diff() == ""


def test_save_creates_a_private_draft_and_never_touches_live(store: DraftStore) -> None:
    store.save(store.current().move(0, 2))
    assert store.has_draft() and store.live_text() == LIVE
    assert stat.S_IMODE(store.draft_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.draft_dir.stat().st_mode) == 0o700
    assert [r["domain"] for r in store.current().rules()][-1] == "a.example.com"
    diff = store.diff()
    assert diff.startswith("--- access_control.yml (live)\n+++ access_control.yml (draft)\n")
    assert "-    - domain: b.example.com" in diff and "+    - domain: b.example.com" in diff


def test_saving_an_unchanged_document_removes_the_draft(store: DraftStore) -> None:
    store.save(store.current().delete(1))
    assert store.has_draft()
    store.save(RulesDocument.parse(LIVE))
    assert not store.has_draft() and not store.meta_path.exists()


def test_draft_goes_stale_when_live_changes(store: DraftStore) -> None:
    store.save(store.current().delete(1))
    assert not store.is_stale()
    store.live_path.write_text(LIVE + "\n# edited by hand over SSH\n")
    assert store.is_stale()
    store.discard()
    assert not store.has_draft() and not store.is_stale()


def test_missing_meta_counts_as_stale(store: DraftStore) -> None:
    store.save(store.current().delete(1))
    store.meta_path.unlink()
    assert store.is_stale()


def test_base_hash_is_kept_across_further_edits(store: DraftStore) -> None:
    store.save(store.current().delete(1))
    first = store.meta_path.read_text()
    store.save(store.current().delete(0))
    assert store.meta_path.read_text() == first


def test_change_summary() -> None:
    live = RulesDocument.parse(LIVE)
    assert summarise(live, live.delete(1)).removed == 1
    moved = summarise(live, live.move(0, 2))
    assert moved.order_changed and not (moved.added or moved.removed or moved.edited)
    node = live.blocks[1].node()
    node["policy"] = "one_factor"
    edited = summarise(live, live.replace_rule(1, node))
    assert (edited.edited, edited.added, edited.removed) == (1, 0, 0)
    added = summarise(
        live, live.insert(3, apply_form(RuleForm(domain=["d.example.com"], policy="deny")))
    )
    assert added.added == 1
    assert summarise(live, live.with_default_policy("one_factor")).default_policy_changed


def test_users_file_yields_names_and_groups_only(tmp_path: Path) -> None:
    secret_hash = "$" + "argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"
    path = tmp_path / "users.yml"
    path.write_text(
        f"users:\n  alice:\n    password: '{secret_hash}'\n    email: a@example.com\n"
        "    groups: [admin, dev]\n  bob:\n    groups: [home]\n"
    )
    info = load_users(path)
    assert info.usernames == {"alice", "bob"} and info.groups == {"admin", "dev", "home"}
    assert info.memberships == {"alice": ("admin", "dev"), "bob": ("home",)}
    assert secret_hash not in repr(info) and "example.com" not in repr(info)
    assert not load_users(tmp_path / "missing.yml").available
    path.write_text("users: [unclosed")
    assert not load_users(path).available


def test_main_definitions_only(tmp_path: Path) -> None:
    path = tmp_path / "configuration.yml"
    path.write_text(
        "session:\n  secret: s3cret-value\ndefinitions:\n  network:\n    vpn: [10.8.0.0/24]\n"
    )
    assert load_main_definitions(path) == {"definitions": {"network": {"vpn": ["10.8.0.0/24"]}}}
    assert load_main_definitions(tmp_path / "missing.yml") == {}


def test_concurrent_edits_cannot_overwrite_each_other(store: DraftStore) -> None:
    """Review finding: two edits based on the same version must not silently overwrite."""
    from app.rules.store import StaleDraftError, sha256

    base = store.current()
    base_sha = sha256(base.render())
    store.save(base.delete(0), expected_sha=base_sha)  # first edit wins
    with pytest.raises(StaleDraftError):
        store.save(base.delete(2), expected_sha=base_sha)  # second, based on the old version
    assert [r["domain"] for r in store.current().rules()] == ["b.example.com", "c.example.com"]
    with pytest.raises(StaleDraftError):
        store.discard(expected_sha=base_sha)
    store.discard(expected_sha=sha256(store.current().render()))
    assert not store.has_draft()
