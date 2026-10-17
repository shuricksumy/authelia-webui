# ruff: noqa: F811  (the `env` fixture is imported from test_web)
"""Backup: a complete, consistent archive that never follows links, and a guarded download."""

from __future__ import annotations

import io
import os
import re
import tarfile
from pathlib import Path

import pytest

from app import backup
from app.apply import audit
from tests.unit.test_web import UI, env  # noqa: F401  (fixture)

KEY = "fake-private-key-for-tests"


def populate(managed: Path) -> None:
    (managed / "secrets" / "jwks").mkdir(parents=True, mode=0o700)
    (managed / "secrets" / "jwks" / "k.pem").write_text(KEY)
    (managed / "secrets").chmod(0o700)
    (managed / ".git").mkdir()
    (managed / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (managed / "audit.log").write_text("{}\n")
    for name in (".draft", ".apply"):
        (managed / name).mkdir()
        (managed / name / "state").write_text("runtime")
    (managed / ".lock").write_text("")


def names(archive: bytes) -> list[str]:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        return tar.getnames()


def test_archive_is_complete_and_leaves_out_runtime_state(env: dict[str, Path]) -> None:
    populate(env["managed"])
    handle, info = backup.make_archive(env["managed"])
    listed = names(handle.read())
    assert "managed/access_control.yml" in listed and "managed/audit.log" in listed
    assert "managed/.git/HEAD" in listed and "managed/secrets/jwks/k.pem" in listed
    assert not [n for n in listed if ".draft" in n or ".apply" in n or n.endswith(".lock")]
    assert info.has_keys and info.files == 4  # the rules, the audit log, git's HEAD, the key


def test_permissions_survive_so_secrets_stay_private(env: dict[str, Path]) -> None:
    populate(env["managed"])
    handle, _ = backup.make_archive(env["managed"])
    with tarfile.open(fileobj=handle, mode="r:gz") as tar:
        assert tar.getmember("managed/secrets").mode & 0o777 == 0o700


def test_symlinks_and_special_files_are_never_archived(
    env: dict[str, Path],
    tmp_path: Path,
) -> None:
    populate(env["managed"])
    outside = tmp_path / "outside.txt"
    outside.write_text("OUTSIDE-SECRET")
    os.symlink(outside, env["managed"] / "link.txt")
    os.symlink(tmp_path, env["managed"] / "dirlink")
    os.mkfifo(env["managed"] / "pipe")
    handle, _ = backup.make_archive(env["managed"])
    blob = handle.read()
    assert b"OUTSIDE-SECRET" not in __import__("gzip").decompress(blob)
    assert not [n for n in names(blob) if "link" in n or n.endswith("pipe")]


def test_a_huge_folder_is_refused(env: dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backup, "MAX_BYTES", 10)
    with pytest.raises(backup.BackupError):
        backup.make_archive(env["managed"])


def test_tokens_are_bound_to_the_user_and_expire() -> None:
    tokens = backup.Tokens("k" * 40)
    good = tokens.issue("alice")
    assert tokens.verify(good, "alice")
    assert not tokens.verify(good, "bob") and not tokens.verify("garbage", "alice")
    assert not tokens.verify(None, "alice") and not tokens.verify(good + "x", "alice")
    assert not backup.Tokens("z" * 40).verify(good, "alice")  # another key


def link_of(ui: UI) -> str:
    page = ui.post("/backup/prepare", {"confirm": "1"}, rev=None).text
    return re.search(r'href="(/backup/download\?token=[^"]+)"', page).group(1)  # type: ignore[union-attr]


def test_download_needs_the_confirmation_then_streams_the_archive(env: dict[str, Path]) -> None:
    populate(env["managed"])
    ui = UI(env)
    assert (
        "BEGIN" not in ui.get("/backup").text and "private signing keys" in ui.get("/backup").text
    )
    refused = ui.post("/backup/prepare", {}, rev=None)
    assert refused.status_code == 422 and "download" not in refused.text.lower().split("tick")[0]
    r = ui.get(link_of(ui).replace("&amp;", "&"))
    assert r.status_code == 200 and r.headers["content-type"] == "application/gzip"
    assert "no-store" in r.headers["cache-control"]
    assert re.fullmatch(r'attachment; filename="authelia-managed-\d{8}-\d{4}\.tar\.gz"',
                        r.headers["content-disposition"])  # fmt: skip
    assert "managed/secrets/jwks/k.pem" in names(r.content)


def test_download_is_audited_without_content(env: dict[str, Path]) -> None:
    populate(env["managed"])
    ui = UI(env)
    ui.get(link_of(ui))
    entry = audit.recent(env["managed"])[-1]
    assert entry.action == "backup" and entry.user == "alice" and "with keys" in entry.summary
    assert KEY not in (env["managed"] / "audit.log").read_text()


def test_a_link_without_a_token_or_from_another_user_is_refused(env: dict[str, Path]) -> None:
    ui = UI(env)
    assert ui.get("/backup/download").status_code == 403
    assert ui.get("/backup/download?token=nope").status_code == 403
    link = link_of(ui)
    other = UI(env, user="carol", groups="admin")
    assert other.get(link).status_code == 403


def test_only_admins_reach_the_backup(env: dict[str, Path]) -> None:
    assert UI(env, user="bob", groups="family").get("/backup").status_code == 403
    assert UI(env, user="bob", groups="family").get("/backup/download").status_code == 403
