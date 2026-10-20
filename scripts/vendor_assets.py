"""Download the vendored front-end libraries at exact versions and record their hashes.

    uv run python -m scripts.vendor_assets          # (re)download and rewrite vendor.lock
    uv run python -m scripts.vendor_assets --check  # verify files against vendor.lock (CI)

All assets are served locally (SPEC §15.1: no CDN at runtime). The lock stores a SHA-384 per
file, so a modified or swapped vendored file fails the unit test.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

VENDOR_DIR = Path(__file__).resolve().parent.parent / "app" / "static" / "vendor"
LOCK = VENDOR_DIR / "vendor.lock"

# name -> (npm package, version, path inside the package, local filename)
ASSETS = {
    "pico": ("@picocss/pico", "2.1.1", "css/pico.min.css", "pico.min.css"),
    "htmx": ("htmx.org", "2.0.11", "dist/htmx.min.js", "htmx.min.js"),
    "sortable": ("sortablejs", "1.15.7", "Sortable.min.js", "Sortable.min.js"),
    # Fonts (SIL Open Font License), Latin subset, variable weight: one file each.
    "inter": (
        "@fontsource-variable/inter",
        "5.2.8",
        "files/inter-latin-wght-normal.woff2",
        "inter.woff2",
    ),
    "jetbrains-mono": (
        "@fontsource-variable/jetbrains-mono",
        "5.2.8",
        "files/jetbrains-mono-latin-wght-normal.woff2",
        "jetbrains-mono.woff2",
    ),
}


def sri(data: bytes) -> str:
    return "sha384-" + base64.b64encode(hashlib.sha384(data).digest()).decode()


def download() -> dict[str, dict[str, str]]:
    lock: dict[str, dict[str, str]] = {}
    for name, (package, version, inner, filename) in ASSETS.items():
        url = f"https://cdn.jsdelivr.net/npm/{package}@{version}/{inner}"
        with urllib.request.urlopen(url, timeout=30) as response:
            data = response.read()
        (VENDOR_DIR / filename).write_bytes(data)
        lock[name] = {
            "package": package,
            "version": version,
            "file": filename,
            "integrity": sri(data),
        }
    return lock


def check() -> list[str]:
    try:
        lock = json.loads(LOCK.read_text())
    except (OSError, ValueError):
        return ["vendor.lock is missing or unreadable"]
    problems = []
    for name, entry in lock.items():
        path = VENDOR_DIR / entry["file"]
        if not path.is_file():
            problems.append(f"{name}: {entry['file']} is missing")
        elif sri(path.read_bytes()) != entry["integrity"]:
            problems.append(f"{name}: {entry['file']} does not match vendor.lock")
    if set(lock) != set(ASSETS):
        problems.append("vendor.lock does not list exactly the expected assets")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    if parser.parse_args().check:
        problems = check()
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0
    LOCK.write_text(json.dumps(download(), indent=2, sort_keys=True) + "\n")
    print(f"vendored {len(ASSETS)} assets into {VENDOR_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
