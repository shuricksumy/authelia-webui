# The users file: measured behaviour (Phase 3)

Measured against the real Authelia container at the pinned version (**4.39.28**) by
`tests/integration/test_users_file.py`, with the users file in `managed/` and
`authentication_backend.file.watch: true`. Re-run on every Authelia bump.

| Question | Result | Consequence for the app |
|---|---|---|
| Does `watch` pick up an **atomic replace** (new inode) of a bind-mounted file? | yes, within ~1-3 s | the configurator writes atomically (temp file + `os.replace`); no restart, nobody signed out |
| Password hashing from the CLI without `--password` | `crypto hash generate` does **not** read stdin: it needs `--password` (visible as a command line) or a terminal | typed passwords are entered on a **pseudo-terminal** (`AutheliaCLI.hash_password`); Enter is CR (raw mode); the prompt does not echo |
| Algorithm and parameters | `--config <main>` applies the configured algorithm (argon2id `m=65536,t=3,p=4` in the fixture) | always hash with `--config` |
| Random passwords | `--config … --random --random.length N --random.charset C` prints `Random Password:`, `Random Password (URL Encoded):` and `Digest:` | generated passwords come from Authelia; parse labels exactly |
| `disabled: true` | login is refused (401) after the reload | |
| Extra attributes | both `extra: {name: value}` and a configured attribute at the user's top level load | keep whichever form a user already has; new values go under `extra:` |
| An **invalid** file on reload | Authelia keeps the previous users and stays healthy (`/api/health` 200); nothing visible from outside | the app must validate before writing: a broken write would silently not take effect |

Default regulation (no `regulation:` section) bans a user after 3 failed logins within 2 minutes;
the measurements make at most one failed attempt per user.
