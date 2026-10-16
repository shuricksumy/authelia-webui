from __future__ import annotations

import pytest

from scripts.check_public_hygiene import scan_text

# Built at runtime so this file itself passes the checker.
HASH = "$" + "argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"
PBKDF2 = "$" + "pbkdf2-sha512$310000$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"
PEM = "-----BEGIN " + "PRIVATE KEY-----"


@pytest.mark.parametrize(
    ("line", "kind"),
    [
        (f"password: {HASH}", "password hash"),
        (f"secret: '{PBKDF2}'", "password hash"),
        (PEM, "PEM block"),
        ("host: 203.0.114.9", "IP outside"),
        ("host: 8.8.8.8", "IP outside"),
        ("url: https://real-site.com/path", "non-example domain"),
        ("mail: someone@gmail.com", "non-example domain"),
        ("cookie domain: photos.trapdoor.me", "non-example domain"),
    ],
)
def test_flags_real_looking_data(line: str, kind: str) -> None:
    findings = scan_text("f.yml", line)
    assert findings and kind in findings[0]
    assert "real-site" not in findings[0] and "8.8.8.8" not in findings[0]  # never echo values


@pytest.mark.parametrize(
    "line",
    [
        "domain: auth.example.com",
        "domain: '*.example.test'",
        "cidr: 192.0.2.10 and 10.8.0.1 and 172.20.0.5 and 192.168.1.1",
        "see https://www.authelia.com/configuration/ and github.com/authelia/authelia",
        "image: ghcr.io/owner/authelia-configurator:authelia-4.39.28",
        "hash prefixes like $argon2id$ and $pbkdf2- in prose",
        "version 4.39.28 and file settings.py",
        "docker compose -f compose.dev.yml up and renovate.json",
        f"x = '{PEM}'  # hygiene: ignore",
    ],
)
def test_allows_documentation_values(line: str) -> None:
    assert scan_text("f.md", line) == []


def test_reports_file_and_line() -> None:
    findings = scan_text("a/b.yml", "ok: 1\nbad: 8.8.4.4\n")
    assert findings == ["a/b.yml:2: IP outside documentation/private ranges"]
