"""Break-glass access: the emergency port ignores Authelia's headers, needs its own password and
session, locks after repeated failures, and does not exist on the normal port."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.apply import audit, notify
from app.apply import state as apply_state
from app.authelia_cli import AutheliaCLI, AutheliaCLIError
from app.emergency import ABSOLUTE_S, IDLE_S, LOCK_S, MAX_FAILS, Emergency
from app.main import create_app
from app.settings import Settings
from tests.unit.test_web import ACCESS_CONTROL

PORT = 8090
RIGHT = "right-emergency-pass"
WRONG = "wrong-guess-1234"
DIGEST = "$" + "argon2id$v=19$m=65536,t=3,p=4$c2FsdA$ZmFrZQ"
GATEWAY = "172.17.0.1"  # where a tunnelled connection comes from inside Docker


def make_settings(tmp_path: Path, **extra: Any) -> Settings:
    managed = tmp_path / "managed"
    managed.mkdir(exist_ok=True)
    (managed / "access_control.yml").write_text(ACCESS_CONTROL)
    users = tmp_path / "users.yml"
    users.write_text("users:\n  alice:\n    groups: [admin]\n")
    main = tmp_path / "configuration.yml"
    main.write_text("theme: light\n")
    values: dict[str, Any] = dict(
        AUTH_DOMAIN="auth.example.com", CONFIGURATOR_DOMAIN="authcfg.example.com",
        ADMIN_GROUP="admin", ALLOWED_CLIENT_CIDRS="10.8.0.0/24",
        TRUSTED_PROXY_CIDRS="172.20.0.0/16", AUTHELIA_CONTAINER="authelia",
        AUTHELIA_HEALTH_URL="http://authelia:9091/api/health", APP_SECRET_KEY="k" * 40,
        CONFIG_MANAGED_DIR=managed, USERS_FILE=users, CONFIG_MAIN=main,
        AUTHELIA_VERSION="4.39.28", EMERGENCY_PORT=PORT, EMERGENCY_PASSWORD_HASH=DIGEST,
    )  # fmt: skip
    values.update(extra)
    return Settings(**values)


@pytest.fixture(autouse=True)
def fake_checker(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def validate(self: AutheliaCLI, password: str, digest: str) -> bool:
        calls.append(password)
        assert digest == DIGEST
        return password == RIGHT

    monkeypatch.setattr(AutheliaCLI, "validate_password", validate)
    return calls


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    monkeypatch.setattr(
        notify, "send",
        lambda settings, event, result, user, summary, commit="": out.append((event, result)),
    )  # fmt: skip
    return out


class Door:
    def __init__(self, tmp_path: Path, port: int = PORT, **extra: Any) -> None:
        self.settings = make_settings(tmp_path, **extra)
        self.app = create_app(self.settings)
        self.client = TestClient(
            self.app, base_url=f"http://localhost:{port}", client=(GATEWAY, 5000),
            follow_redirects=False,
        )  # fmt: skip

    def login(self, password: str = RIGHT) -> Any:
        return self.client.post(
            "/emergency/login", data={"password": password},
            headers={"Origin": f"http://localhost:{PORT}"},
        )  # fmt: skip

    def signed_in(self) -> Door:
        assert self.login().status_code == 303
        return self

    def csrf(self) -> str:
        page = self.client.get("/rules").text
        return re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)  # type: ignore[union-attr]


@pytest.fixture
def door(tmp_path: Path) -> Door:
    return Door(tmp_path)


def test_without_a_session_everything_but_the_login_redirects(door: Door) -> None:
    r = door.client.get("/rules")
    assert r.status_code == 303 and r.headers["location"] == "/emergency/login"
    assert door.client.post("/rules/move", data={}).status_code == 403
    assert door.client.get("/emergency/login").status_code == 200
    assert door.client.get("/healthz").text == "ok"
    assert door.client.get("/static/app.css").status_code == 200


def test_authelias_headers_buy_nothing_here(door: Door) -> None:
    forged = {"Remote-User": "alice", "Remote-Groups": "admin", "X-Forwarded-For": "10.8.0.5"}
    assert door.client.get("/rules", headers=forged).status_code == 303
    assert door.client.get("/keys", headers=forged).status_code == 303


@pytest.mark.parametrize("host", ["evil.example.com:8090", "localhost.example.org:8090",
                                  "authcfg.example.com", "127.0.0.1.example.org:8090",
                                  "localhost:80x", "[::1]x:8090", ""])  # fmt: skip
def test_only_loopback_host_names_are_served(door: Door, host: str) -> None:
    assert door.client.get("/emergency/login", headers={"host": host}).status_code == 403
    assert door.client.post(
        "/emergency/login", data={"password": RIGHT}, headers={"host": host}
    ).status_code == 403  # fmt: skip


def test_the_loopback_address_works_too(door: Door) -> None:
    r = door.client.get("/emergency/login", headers={"host": f"127.0.0.1:{PORT}"})
    assert r.status_code == 200


def test_a_good_password_signs_in_with_a_strict_http_only_cookie(
    door: Door, sent: list[tuple[str, str]]
) -> None:
    r = door.login()
    assert r.status_code == 303 and r.headers["location"] == "/"
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Path=/" in cookie
    page = door.client.get("/rules")
    assert page.status_code == 200 and "Emergency access." in page.text
    assert "emergency <small>(admin)</small>" in page.text
    assert "emergency_session=" in page.headers["set-cookie"]  # the idle timer is renewed
    assert ("emergency login", "success") in sent


def test_a_wrong_password_is_refused_and_audited_without_the_password(
    door: Door, tmp_path: Path
) -> None:
    r = door.login(WRONG)
    assert r.status_code == 401 and "Wrong password" in r.text
    assert "set-cookie" not in r.headers
    assert door.client.get("/rules").status_code == 303
    entry = audit.recent(door.settings.CONFIG_MANAGED_DIR)[-1]
    assert entry.action == "emergency-login" and entry.result == "failed"
    blob = (door.settings.CONFIG_MANAGED_DIR / "audit.log").read_text()
    blob += str(apply_state.load(door.settings.CONFIG_MANAGED_DIR))
    assert WRONG not in blob and RIGHT not in blob


def test_five_wrong_passwords_lock_the_login_even_for_the_right_one(
    door: Door, fake_checker: list[str], sent: list[tuple[str, str]]
) -> None:
    for _ in range(MAX_FAILS - 1):
        assert door.login(WRONG).status_code == 401
    locked = door.login(WRONG)
    assert locked.status_code == 429 and "Try again in 15 minutes" in locked.text
    checked = len(fake_checker)
    again = door.login(RIGHT)
    assert again.status_code == 429 and "set-cookie" not in again.headers
    assert len(fake_checker) == checked  # a locked login does not even look at the password
    assert ("emergency login", "locked") in sent
    assert "Too many wrong passwords" in door.client.get("/emergency/login").text


def test_the_lockout_survives_a_restart_and_ends(tmp_path: Path) -> None:
    first = Door(tmp_path)
    for _ in range(MAX_FAILS):
        first.login(WRONG)
    second = Door(tmp_path)  # a new process: the state is on disk
    assert second.login(RIGHT).status_code == 429
    em: Emergency = second.app.state.emergency
    assert em.locked_for(GATEWAY, time.time() + LOCK_S + 1) == 0
    path = second.settings.CONFIG_MANAGED_DIR / ".apply" / "emergency.json"
    data = json.loads(path.read_text())
    data["ips"][GATEWAY]["locked_until"] = time.time() - 1
    path.write_text(json.dumps(data))
    assert second.login(RIGHT).status_code == 303


def test_a_success_resets_the_failure_count(door: Door) -> None:
    for _ in range(MAX_FAILS - 1):
        door.login(WRONG)
    assert door.login(RIGHT).status_code == 303
    for _ in range(MAX_FAILS - 1):
        assert door.login(WRONG).status_code == 401  # a fresh allowance


def test_a_checker_failure_is_not_a_wrong_guess(
    door: Door, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(self: AutheliaCLI, password: str, digest: str) -> bool:
        raise AutheliaCLIError("boom")

    monkeypatch.setattr(AutheliaCLI, "validate_password", broken)
    for _ in range(MAX_FAILS + 2):
        assert door.login(RIGHT).status_code == 503
    assert Emergency(door.settings).locked_for(GATEWAY) == 0


def test_cookies_expire_and_cannot_be_forged(tmp_path: Path) -> None:
    em = Emergency(make_settings(tmp_path))
    now = time.time()
    assert em.read(em.issue(now), now) == pytest.approx(now)
    assert em.read(em.issue(now - ABSOLUTE_S - 5), now) is None  # past the 2 h limit
    assert em.read(em.issue(now) + "x", now) is None and em.read("junk", now) is None
    assert em.read(None, now) is None and em.read("", now) is None
    other = Emergency(make_settings(tmp_path, APP_SECRET_KEY="z" * 40))
    assert em.read(other.issue(now), now) is None
    assert IDLE_S == 1800


def test_an_idle_cookie_is_rejected(door: Door, monkeypatch: pytest.MonkeyPatch) -> None:
    door.signed_in()
    real = time.time
    monkeypatch.setattr("itsdangerous.timed.time.time", lambda: real() + IDLE_S + 60)
    assert door.client.get("/rules").status_code == 303


def test_posts_need_the_csrf_token_and_a_local_origin(door: Door) -> None:
    door.signed_in()
    token = door.csrf()
    url = "/rules/default-policy"
    form = {"policy": "deny", "rev": "x"}
    local = {"Origin": f"http://localhost:{PORT}"}
    assert door.client.post(url, data=form, headers=local).status_code == 403  # no token
    assert (
        door.client.post(url, data=form, headers={**local, "X-CSRF-Token": "junk"}).status_code
        == 403
    )
    foreign = {"Origin": "http://evil.example.com", "X-CSRF-Token": token}
    assert door.client.post(url, data=form, headers=foreign).status_code == 403
    ok = door.client.post(url, data=form, headers={**local, "X-CSRF-Token": token})
    assert ok.status_code != 403


def test_logout_clears_the_cookie(door: Door) -> None:
    door.signed_in()
    r = door.client.post(
        "/emergency/logout",
        headers={"Origin": f"http://localhost:{PORT}", "X-CSRF-Token": door.csrf()},
    )
    assert r.status_code == 204 and "Max-Age=0" in r.headers["set-cookie"]
    assert r.headers["hx-redirect"] == "/emergency/login"
    door.client.cookies.clear()
    assert door.client.get("/rules").status_code == 303


def test_the_normal_port_has_no_emergency_door(tmp_path: Path) -> None:
    normal = Door(tmp_path, port=8080)
    headers = {"Remote-User": "alice", "Remote-Groups": "admin", "X-Forwarded-For": "10.8.0.5"}
    normal.client = TestClient(  # through the proxy, as Traefik would
        normal.app, base_url="https://authcfg.example.com", client=("172.20.0.2", 5000),
        follow_redirects=False,
    )  # fmt: skip
    assert normal.client.get("/rules", headers=headers).status_code == 200
    assert normal.client.get("/emergency/login", headers=headers).status_code == 404
    tunnel = Door(tmp_path, port=8080)  # a loopback Host on the normal port is just refused
    assert tunnel.client.get("/rules", headers=headers).status_code == 403
    post = normal.client.post("/emergency/login", data={"password": RIGHT}, headers=headers)
    assert post.status_code in (403, 404)


def test_without_the_setting_there_is_no_emergency_login(tmp_path: Path) -> None:
    off = Door(tmp_path, EMERGENCY_PORT=None, EMERGENCY_PASSWORD_HASH=None)
    assert off.client.get("/emergency/login").status_code == 403  # normal rules: no identity
    assert not off.app.state.emergency.enabled


def test_settings_demand_both_values_and_a_sane_port(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="set together"):
        make_settings(tmp_path, EMERGENCY_PASSWORD_HASH=None)
    with pytest.raises(ValidationError, match="set together"):
        make_settings(tmp_path, EMERGENCY_PORT=None)
    with pytest.raises(ValidationError, match="differ from the application port"):
        make_settings(tmp_path, EMERGENCY_PORT=8080)
    with pytest.raises(ValidationError, match="Authelia password digest"):
        make_settings(tmp_path, EMERGENCY_PASSWORD_HASH="plaintext-password")
    with pytest.raises(ValidationError):
        make_settings(tmp_path, EMERGENCY_PORT=80)
    unset = make_settings(tmp_path, EMERGENCY_PORT="", EMERGENCY_PASSWORD_HASH="")
    assert unset.EMERGENCY_PORT is None and unset.EMERGENCY_PASSWORD_HASH is None


def test_the_digest_never_appears_in_a_page_or_a_repr(door: Door) -> None:
    door.signed_in()
    for path in ("/rules", "/history", "/keys", "/logs", "/backup"):
        assert DIGEST not in door.client.get(path).text
    assert DIGEST not in repr(door.settings)


def test_emergency_sessions_can_use_the_backup(door: Door) -> None:
    door.signed_in()
    token = door.csrf()
    page = door.client.post(
        "/backup/prepare", data={"confirm": "1"},
        headers={"Origin": f"http://localhost:{PORT}", "X-CSRF-Token": token},
    )  # fmt: skip
    link = re.search(r'href="(/backup/download\?token=[^"]+)"', page.text).group(1)  # type: ignore[union-attr]
    r = door.client.get(link)
    assert r.status_code == 200 and r.headers["content-type"] == "application/gzip"
    assert audit.recent(door.settings.CONFIG_MANAGED_DIR)[-1].user == "emergency"


def test_a_browsers_login_form_posts_origin_null_under_no_referrer(door: Door) -> None:
    """`Referrer-Policy: no-referrer` makes browsers send `Origin: null` on a plain form POST."""
    post = door.client.post
    same = {"Origin": "null", "Sec-Fetch-Site": "same-origin"}
    assert post("/emergency/login", data={"password": WRONG}, headers=same).status_code == 401
    assert post("/emergency/login", data={"password": RIGHT}, headers=same).status_code == 303
    # a page on another site can also send `null` (its own no-referrer policy): refused
    cross = {"Origin": "null", "Sec-Fetch-Site": "cross-site"}
    assert post("/emergency/login", data={"password": RIGHT}, headers=cross).status_code == 403
    assert post("/emergency/login", data={"password": RIGHT},
                headers={"Origin": "null"}).status_code == 403  # fmt: skip
    # and `null` is never enough for anything but the login
    token = door.csrf()
    other = {"Origin": "null", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": token}
    assert post("/rules/default-policy", data={"policy": "deny"}, headers=other).status_code == 403
    assert post("/emergency/logout", headers=other).status_code == 403


def test_other_loopback_ports_work_and_the_origin_must_match_the_host(door: Door) -> None:
    tunnel = {"host": "localhost:9999"}  # `ssh -L 9999:127.0.0.1:8090` is the admin's choice
    assert door.client.get("/emergency/login", headers=tunnel).status_code == 200
    ok = door.client.post("/emergency/login", data={"password": WRONG},
                          headers={**tunnel, "Origin": "http://localhost:9999"})  # fmt: skip
    assert ok.status_code == 401
    other = door.client.post("/emergency/login", data={"password": RIGHT},
                             headers={**tunnel, "Origin": "http://localhost:8090"})  # fmt: skip
    assert other.status_code == 403  # another local origin is another site
    assert door.client.get("/emergency/login", headers={"host": "[::1]:8090"}).status_code == 200


def test_another_address_cannot_lock_the_owner_out(tmp_path: Path) -> None:
    owner = Door(tmp_path)
    neighbour = TestClient(owner.app, base_url=f"http://localhost:{PORT}",
                           client=("172.30.0.66", 5000), follow_redirects=False)  # fmt: skip
    for _ in range(MAX_FAILS + 3):  # e.g. a compromised app container on the same network
        neighbour.post("/emergency/login", data={"password": WRONG},
                       headers={"Origin": f"http://localhost:{PORT}"})  # fmt: skip
    assert owner.login(RIGHT).status_code == 303  # the tunnel arrives from another address


def test_many_addresses_together_hit_the_global_ceiling(tmp_path: Path) -> None:
    from app.emergency import GLOBAL_MAX_FAILS

    door = Door(tmp_path)
    for n in range(GLOBAL_MAX_FAILS):
        attacker = TestClient(
            door.app, base_url=f"http://localhost:{PORT}", client=(f"172.30.1.{n + 1}", 5000),
            follow_redirects=False,
        )  # fmt: skip
        attacker.post("/emergency/login", data={"password": WRONG},
                      headers={"Origin": f"http://localhost:{PORT}"})  # fmt: skip
    assert door.login(RIGHT).status_code == 429  # guessing stays bounded


def test_attempts_against_a_lock_do_not_flood_the_audit_log(door: Door) -> None:
    for _ in range(MAX_FAILS):
        door.login(WRONG)
    lines = len((door.settings.CONFIG_MANAGED_DIR / "audit.log").read_text().splitlines())
    for _ in range(50):
        assert door.login(WRONG).status_code == 429
    after = len((door.settings.CONFIG_MANAGED_DIR / "audit.log").read_text().splitlines())
    assert after == lines


def test_sign_out_ends_every_copy_of_the_session(door: Door) -> None:
    door.signed_in()
    stolen = door.client.cookies.get("emergency_session")
    door.client.post("/emergency/logout", headers={"Origin": f"http://localhost:{PORT}",
                                                   "X-CSRF-Token": door.csrf()})  # fmt: skip
    door.client.cookies.clear()
    replay = door.client.get("/rules", headers={"Cookie": f"emergency_session={stolen}"})
    assert replay.status_code == 303  # a copy of the cookie is worthless after sign-out


def test_a_new_password_ends_old_sessions(tmp_path: Path) -> None:
    door = Door(tmp_path).signed_in()
    cookie = door.client.cookies.get("emergency_session")
    rotated = Door(tmp_path, EMERGENCY_PASSWORD_HASH=DIGEST.replace("ZmFrZQ", "bmV3"))
    assert rotated.client.get("/rules", headers={"Cookie": f"emergency_session={cookie}"}
                              ).status_code == 303  # fmt: skip


def test_a_csrf_token_from_the_normal_door_is_refused_here(door: Door) -> None:
    from app.security import CSRF

    door.signed_in()
    normal_token = CSRF("k" * 40).issue("emergency")  # what the normal port would issue
    r = door.client.post("/rules/default-policy", data={"policy": "deny"},
                         headers={"Origin": f"http://localhost:{PORT}",
                                  "X-CSRF-Token": normal_token})  # fmt: skip
    assert r.status_code == 403
