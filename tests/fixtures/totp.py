"""Print the dev login for the local stack (`make totp`): username, password and the current
TOTP code. The credentials are generated per `make stack` run and live in the gitignored
tests/fixtures/generated/credentials.json."""

from __future__ import annotations

import json
import time

import pyotp

from tests.e2e.auth import CREDENTIALS
from tests.fixtures.stack import AUTH_HOST, CONFIGURATOR_HOST, INTERNAL_PORT


def main() -> int:
    try:
        creds = json.loads(CREDENTIALS.read_text())
    except OSError:
        print("No test stack yet: run `make dev` first.")
        return 1
    totp = pyotp.TOTP(creds["totp_secret"])
    remaining = 30 - int(time.time()) % 30
    print(f"https://{CONFIGURATOR_HOST}:{INTERNAL_PORT}   (accept the self-signed certificate)")
    print(f"username: {creds['username']}")
    print(f"password: {creds['password']}")
    print(f"2FA code: {totp.now()}   (valid for {remaining}s; Authelia rejects a code used twice)")
    print(f"hosts:    127.0.0.1 {AUTH_HOST} {CONFIGURATOR_HOST} locked.example.test")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
