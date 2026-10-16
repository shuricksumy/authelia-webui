"""Access test suite, live verification, notifications and main-config tracking (SPEC §16)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from app.apply import notify
from app.apply import state as apply_state
from app.rules import access_tests
from app.rules.access_tests import AccessCase
from app.rules.document import DocumentError, RulesDocument
from app.rules.store import DraftStore
from tests.unit.test_apply import (
    draft_move,
    env,  # noqa: F401  (fixture)
    git,
    live,
    make,
    run,
)
from tests.unit.test_web import ACCESS_CONTROL

TESTS = """- name: photos ping is public
  url: https://photos.example.com/api/ping
  expect: bypass
- url: https://photos.example.com/library
  user: bob
  groups: [family]
  expect: two_factor
- url: https://photos.example.com/library
  expect: two_factor
- url: https://authcfg.example.com/
  ip: 203.0.113.9
  expect: deny
"""


def write_tests(managed: Path, text: str = TESTS) -> None:
    (managed / "access_tests.yml").write_text(text)


def config(text: str = ACCESS_CONTROL) -> dict[str, Any]:
    return RulesDocument.parse(text).effective()


# --------------------------------------------------------------------- file format


def test_parse_and_render_round_trip() -> None:
    cases = access_tests.parse(TESTS)
    assert [c.expect for c in cases] == ["bypass", "two_factor", "two_factor", "deny"]
    assert cases[1].groups == ("family",) and cases[0].name == "photos ping is public"
    assert access_tests.parse(access_tests.render(cases)) == cases


@pytest.mark.parametrize(
    ("text", "fragment"),
    [("- url: https://a.example.com/\n  expect: allow\n", "expect must be"),
     ("- url: /relative\n  expect: deny\n", "absolute"),
     ("- url: https://a.example.com/\n  ip: nope\n  expect: deny\n", "ip"),
     ("url: x\n", "list"), ("- just text\n", "not a mapping"), ("- [unclosed\n", "YAML")],
)  # fmt: skip
def test_invalid_test_files_explain_the_problem(text: str, fragment: str) -> None:
    with pytest.raises(DocumentError, match=fragment):
        access_tests.parse(text)


# --------------------------------------------------------------------- evaluation


def test_evaluate_on_live_and_draft_flags_changes_and_failures() -> None:
    cases = access_tests.parse(TESTS)
    doc = RulesDocument.parse(ACCESS_CONTROL)
    draft = doc.delete(3)  # remove the photos ping bypass
    import ipaddress

    results = access_tests.evaluate(cases, config(), draft.effective(),
                                    ipaddress.ip_address("10.8.0.5"))  # fmt: skip
    assert [r.live.policy for r in results] == ["bypass", "two_factor", "two_factor", "deny"]
    assert results[0].changed and results[0].fails  # ping is no longer public
    assert not any(r.fails for r in results[1:])
    assert [r.case.url for r in access_tests.failing(results)] == [cases[0].url]


def test_the_network_of_a_case_matters() -> None:
    """The configurator rule allows only 10.8.0.0/24: an outside IP is denied."""
    import ipaddress

    inside = AccessCase("https://authcfg.example.com/", "two_factor", user="alice",
                        groups=("admin",))  # fmt: skip
    outside = AccessCase("https://authcfg.example.com/", "deny", user="alice", groups=("admin",),
                         ip="203.0.113.9")  # fmt: skip
    results = access_tests.evaluate([inside, outside], config(), None,
                                    ipaddress.ip_address("10.8.0.5"))  # fmt: skip
    assert [r.live.policy for r in results] == ["two_factor", "deny"]
    assert not any(r.fails for r in results)


# --------------------------------------------------------------------- engine: gate + verify


def test_failing_tests_block_apply_unless_accepted(env: dict[str, Any]) -> None:  # noqa: F811
    write_tests(env["managed"])
    store: DraftStore = env["store"]
    store.save(store.current().delete(3))  # breaks the "ping is public" expectation
    rev = store.current_sha()[:16]
    engine, runtime, _ = make(env, [True])
    reasons = " ".join(engine.preconditions(rev=rev))
    assert "1 access test(s) would not get the expected result" in reasons
    job = run(engine, rev)
    assert job.result == "refused" and runtime.restarts == 0
    from app.apply.engine import ApplyRequest

    job2 = engine.board.new("alice")
    engine.apply(ApplyRequest("alice", "10.8.0.5", rev, accept_tests=True), job2)
    assert job2.result == "applied", job2.message


def harmless_draft(env: dict[str, Any]) -> str:  # noqa: F811
    """A change that leaves every access test's outcome alone (all cases match a rule)."""
    store: DraftStore = env["store"]
    store.save(store.current().with_default_policy("one_factor"))
    return store.current_sha()[:16]


def fake_prober(answers: dict[str, str]) -> Any:
    def prober(url: str, case: AccessCase, client_ip: str) -> tuple[str, str]:
        assert url == "http://authelia:9091"  # derived from AUTHELIA_HEALTH_URL
        return answers.get(case.url, "untestable"), ""

    return prober


def test_verify_passes_when_authelia_behaves_as_previewed(env: dict[str, Any]) -> None:  # noqa: F811
    write_tests(env["managed"])
    rev = harmless_draft(env)
    engine, _, _ = make(env, [True])
    engine.prober = fake_prober({
        "https://photos.example.com/api/ping": "allow",
        "https://photos.example.com/library": "login",
        "https://authcfg.example.com/": "deny",
    })  # fmt: skip
    job = run(engine, rev)
    assert job.result == "applied", job.message
    assert job.step("verify").status == "done" and job.step("verify").detail == "3 checked"


def test_verify_mismatch_rolls_back_and_names_the_requests(env: dict[str, Any]) -> None:  # noqa: F811
    write_tests(env["managed"])
    original = live(env)
    rev = harmless_draft(env)
    engine, runtime, _ = make(env, [True, True])
    engine.prober = fake_prober({
        "https://photos.example.com/api/ping": "login",  # Authelia did not load the bypass
        "https://photos.example.com/library": "login",
        "https://authcfg.example.com/": "deny",
    })  # fmt: skip
    job = run(engine, rev)
    assert job.result == "rolled-back", job.message
    assert "does not behave as previewed for 1 access test" in job.message
    assert any("api/ping: previewed allow, Authelia says login" in d for d in job.details)
    assert live(env) == original and runtime.restarts == 2
    assert job.step("verify").status == "failed"


def test_untestable_requests_do_not_cause_a_rollback(env: dict[str, Any]) -> None:  # noqa: F811
    write_tests(env["managed"])
    rev = harmless_draft(env)
    engine, _, _ = make(env, [True])
    engine.prober = fake_prober({"https://photos.example.com/api/ping": "allow"})
    job = run(engine, rev)
    assert job.result == "applied", job.message
    assert job.step("verify").detail == "1 checked, 2 not testable"


# --------------------------------------------------------------------- notifications, main sha


def test_notification_payload_has_no_configuration_content(
    env: dict[str, Any],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(notify, "_post", lambda url, body: sent.append((url, body)))
    env["settings"].NOTIFY_WEBHOOK_URL = SecretStr("https://hooks.example.com/t/secret-token")
    engine, _, _ = make(env, [True])
    run(engine, draft_move(env))
    for _ in range(50):
        if sent:
            break
        import time

        time.sleep(0.02)
    url, body = sent[0]
    assert url.endswith("secret-token")
    assert body["event"] == "apply" and body["result"] == "applied" and body["user"] == "alice"
    assert {"title", "message", "text", "commit", "ts", "host"} <= set(body)
    flat = repr(body)
    assert "photos.example.com" not in flat and "secret-token" not in flat and "policy" not in flat


def test_no_webhook_configured_sends_nothing(env: dict[str, Any]) -> None:  # noqa: F811
    assert notify.send(env["settings"], "apply", "applied", "alice", "ok") is False


def test_a_failing_webhook_never_breaks_the_apply(env: dict[str, Any]) -> None:  # noqa: F811
    env["settings"].NOTIFY_WEBHOOK_URL = SecretStr("http://127.0.0.1:9/unreachable")
    engine, _, _ = make(env, [True])
    assert run(engine, draft_move(env)).result == "applied"


def test_main_config_hash_is_recorded_on_import_and_after_apply(env: dict[str, Any]) -> None:  # noqa: F811
    engine, _, _ = make(env, [True])
    run(engine, draft_move(env))
    recorded = apply_state.load(env["managed"])["main_sha"]
    assert recorded == engine.main_config_sha() != ""
    env["settings"].CONFIG_MAIN.write_text("theme: dark\n")
    assert engine.main_config_sha() != apply_state.load(env["managed"])["main_sha"]


def test_external_commit_outside_apply_records_state_and_audit(env: dict[str, Any]) -> None:  # noqa: F811
    engine, _, _ = make(env)
    engine.repo.ensure(["access_control.yml"])
    assert engine.commit_external_changes() is None  # nothing changed
    path = env["managed"] / "access_control.yml"
    path.write_text(path.read_text() + "# hand edit\n")
    sha = engine.commit_external_changes()
    assert sha and apply_state.load(env["managed"])["external"]["commit"] == sha
    assert git(env["managed"], "log", "--format=%an", "-n1").strip() == "external"


def test_version_mismatch_is_notified_once_per_running_version(
    env: dict[str, Any],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.apply.status import StatusCache
    from tests.unit.test_apply import FakeRuntime

    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(notify, "_post", lambda url, body: sent.append(body))
    env["settings"].NOTIFY_WEBHOOK_URL = SecretStr("https://hooks.example.com/x")
    runtime = FakeRuntime(version="4.40.0")
    for _ in range(3):
        StatusCache(env["settings"], runtime, check=lambda url: True).get(fresh=True)  # type: ignore[arg-type]
    runtime.version = "4.41.0"
    StatusCache(env["settings"], runtime, check=lambda url: True).get(fresh=True)  # type: ignore[arg-type]
    import time

    time.sleep(0.2)
    assert [b["event"] for b in sent] == ["version-mismatch", "version-mismatch"]
    assert "4.40.0" in sent[0]["message"] and "4.41.0" in sent[1]["message"]
