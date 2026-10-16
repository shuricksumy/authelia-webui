"""Block real-looking data in a public repository (SPEC §13).

Flags password hashes, PEM blocks, IPs outside documentation/private ranges and
domains other than example.* / *.example.test / a reference allowlist. Findings
report file, line and kind only, never the matched text.

    python -m scripts.check_public_hygiene            # all tracked + untracked files
    python -m scripts.check_public_hygiene FILE...
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

# Vendored third-party assets are hash-locked (vendor.lock) and carry their own project URLs.
SKIP_PREFIXES = ("tests/fixtures/generated/", ".git/", ".venv/", "app/static/vendor/")
# Deliberate bad samples live here; this is the checker's own test.
SKIP_FILES = {"tests/unit/test_hygiene.py"}
SKIP_NAMES = {"uv.lock"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".gz", ".whl"}

HASH_PATTERNS = [
    re.compile(r"\$argon2id?\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+"),
    re.compile(r"\$pbkdf2-sha\d+\$\d+\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+"),
]
PEM = re.compile(r"-----BEGIN (?:[A-Z]+ )*(?:PRIVATE KEY|CERTIFICATE|PUBLIC KEY)-----")
IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
# ".app" is deliberately absent: it collides with attribute access (`outputs.app`, `self.app`).
TLDS = (
    "com|net|org|io|me|dev|ru|ua|de|uk|fr|eu|info|biz|co|us|cc|xyz|online|site|cloud|"
    "tech|sh|ai|pl|nl|cz|it|es|se|no|fi|ch|at|be|pt|tv|to|im"
)
DOMAIN = re.compile(
    rf"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:{TLDS}))(?![\w-])", re.I
)
EMAIL = re.compile(rf"[\w.+-]+@((?:[a-z0-9-]+\.)+(?:{TLDS}))\b", re.I)

# example.* per RFC 2606 and *.example.test; plus reference sites the docs link to.
ALLOWED_DOMAINS = {
    "example.com", "example.org", "example.net",
    "authelia.com", "github.com", "githubusercontent.com", "ghcr.io", "docker.io",
    "docker.com", "python.org", "pypi.org", "astral.sh", "traefik.io", "mkjwk.org",
    "anthropic.com", "claude.com", "claude.ai", "sigstore.dev", "renovatebot.com",
    "gitleaks.io", "pre-commit.com", "trivy.dev", "json.schemastore.org", "schemastore.org",
    "apache.org", "jsdelivr.net", "htmx.org", "ntfy.sh", "gotify.net", "home-assistant.io",
    "cloudflare.com",
}  # fmt: skip
ALLOWED_SUFFIXES = (".example.com", ".example.org", ".example.net", ".example.test")
# Typical file names that look like domains.
IGNORED_NAMES = {"node.js", "next.js", "vue.js", "main.py"}

_DOC_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "0.0.0.0/32",
        "255.255.255.255/32",
    )
]  # fmt: skip


def _domain_ok(host: str) -> bool:
    host = host.lower()
    if host in IGNORED_NAMES:
        return True
    return host in ALLOWED_DOMAINS or host.endswith(
        (*ALLOWED_SUFFIXES, *(f".{d}" for d in ALLOWED_DOMAINS))
    )


def scan_text(path: str, text: str) -> list[str]:
    findings: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if "hygiene: ignore" in line:
            continue
        if any(p.search(line) for p in HASH_PATTERNS):
            findings.append(f"{path}:{lineno}: password hash")
        if PEM.search(line):
            findings.append(f"{path}:{lineno}: PEM block")
        for match in IPV4.finditer(line):
            try:
                ip = ipaddress.ip_address(match.group(1))
            except ValueError:
                continue
            if not any(ip in net for net in _DOC_NETS):
                findings.append(f"{path}:{lineno}: IP outside documentation/private ranges")
        hosts = {m.group(1) for m in DOMAIN.finditer(line)} | {
            m.group(1) for m in EMAIL.finditer(line)
        }
        findings.extend(
            f"{path}:{lineno}: non-example domain" for host in sorted(hosts) if not _domain_ok(host)
        )
    return findings


def _skip(path: str) -> bool:
    p = Path(path)
    return (
        path.startswith(SKIP_PREFIXES)
        or path in SKIP_FILES
        or p.name in SKIP_NAMES
        or p.suffix.lower() in SKIP_SUFFIXES
    )


def scan_files(paths: Iterable[str]) -> list[str]:
    findings: list[str] = []
    for path in paths:
        if _skip(path):
            continue
        try:
            text = Path(path).read_text()
        except (UnicodeDecodeError, OSError):
            continue
        findings.extend(scan_text(path, text))
    return findings


def _default_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        capture_output=True, text=True, check=True,
    ).stdout  # fmt: skip
    return [p for p in out.splitlines() if p and Path(p).is_file()]


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    findings = scan_files(args or _default_files())
    for finding in findings:
        print(finding, file=sys.stderr)
    if findings:
        print(f"{len(findings)} public-hygiene finding(s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
