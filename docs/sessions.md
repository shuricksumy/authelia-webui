# Open sessions: see who is signed in, sign people out

An optional feature. With it, the configurator shows who is signed in to Authelia right now and
can end sessions: **one session**, **all sessions of one user**, or **everyone's**. The account
stays enabled, so the person simply has to sign in again.

It is off until you switch it on, and nothing changes for you if you never do.

## What you get

- **Users page:** a *Sessions* column (how many each user has) and a **Sign out all users**
  button. Your own session is kept, so you are not signed out mid-action.
- **A user's editor** (the pencil), at the bottom: *Open sessions*. Each session shows its level
  (1FA or 2FA), when it was last active, when it was signed in and when 2FA was completed, how long
  it still lasts, "stays signed in" for *remember me*, and a short id such as `#a1b2c3`. Each has a
  **Sign out** button, and **Sign out everywhere** ends them all. For yourself it reads *Sign out
  my other sessions* and keeps the browser you are using.
- **Overview:** an *Open sessions* card, and a "needs attention" item if Redis cannot be read.

Authelia stores no IP address, browser or device per session, so those cannot be shown.

## What it needs

**Authelia's sessions in Redis.** The production example already does this (the `redis` service and
`session.redis` in `configuration.example.yml`). If your `session:` block has no `redis:` section,
sessions live inside Authelia's own memory, which nothing outside can reach; this feature does not
apply. (A restart of Authelia ends all memory sessions, which is the only "sign out everyone" there
is in that case.)

## Setup

Run these in the folder that holds your `compose.yml`.

1. **Authelia's session secret as a file.** It must be exactly the value of `session.secret` from
   your Authelia configuration: the sessions are encrypted with it.
   ```sh
   mkdir -p secrets
   printf %s 'THE-VALUE-OF-session.secret' > secrets/session_secret
   ```
   The configurator runs as `AUTHELIA_UID:AUTHELIA_GID` from your `.env`, so give the file to that
   user. **Use the numbers, not the variable names**: those variables exist in `.env`, not in your
   shell, and `chown "$AUTHELIA_UID:..."` would silently do nothing.
   ```sh
   sudo chown 1000:1000 secrets/session_secret && sudo chmod 400 secrets/session_secret
   ```
2. **A password for the configurator's Redis user:**
   ```sh
   echo "CONFIGURATOR_REDIS_PASSWORD=$(openssl rand -hex 24)" >> .env
   ```
3. **Start it with the add-on file**, which creates that Redis user, passes the settings and joins
   the configurator to the Redis network:
   ```sh
   docker compose -f compose.yml -f compose.sessions.yml up -d
   ```
   Redis restarts. Your example saves sessions to disk, so nobody is signed out, but pick a quiet
   moment. To keep the extra file in every command, add `COMPOSE_FILE=compose.yml:compose.sessions.yml`
   to `.env`.
4. **Check it.** Sign in from a second browser, open the first browser's Users page, then the
   user's editor: you should see two sessions. Press **Sign out everywhere** and click anything in
   the second browser: it asks you to sign in.

[`examples/production/compose.sessions.yml`](../examples/production/compose.sessions.yml) is the
whole add-on, with comments.

**Your own compose file, with other names?** The add-on assumes the example's names: a Redis
service called `redis` on a network called `sessions`. If yours differ (say Redis is
`authelia-redis`), change three things:

1. Rename the `redis:` key in `compose.sessions.yml` to your Redis **service** name. Otherwise
   Compose adds a second service called `redis` that has no image, and refuses to start. (Or copy
   the `--user ...` arguments onto your own Redis command by hand.)
2. Point `SESSIONS_REDIS_URL` at it: `redis://authelia-redis:6379/0`.
3. Under the configurator's `networks:`, use the network your Redis is on instead of `sessions`
   (and declare it if the file does not already). `docker inspect authelia-redis --format
   '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}'` lists it, with Compose's project
   prefix in front.

Also keep the same `REDIS_PASSWORD` value for Redis and for Authelia that you use today. If Redis
has no password (`docker exec <redis> redis-cli ping` answers `PONG`), the add-on still works, but
set one: nothing but Authelia and the configurator should be able to reach it.

### The settings

Set in the add-on file; listed here for other setups. The address and the secret file go together.

| Setting | Default | |
|---|---|---|
| `SESSIONS_REDIS_URL` | unset (feature off) | `redis://host:6379/0`, or `rediss://` for TLS. The number is Authelia's `database_index`; for any number but 0, add `+select` to the Redis user's rules (below). Credentials in the URL are refused: URLs end up in logs. |
| `SESSIONS_REDIS_USERNAME` | `configurator` | The Redis user below. |
| `SESSIONS_REDIS_PASSWORD` | none | Its password. |
| `SESSIONS_SECRET_FILE` | unset (feature off) | A file holding Authelia's `session.secret`. Read each time, so rotating it needs no restart. |
| `SESSIONS_COOKIE_NAME` | `authelia_session` | Only if you renamed Authelia's `session.name`. It is how "keep my current session" recognises yours. |

## What the Redis user may do

The add-on creates it with this line, in Redis's own configuration (a user added later by hand
would be lost when Redis restarts):

```
--user configurator on >PASSWORD ~authelia-session:* -@all +scan +get +del +pttl +ping
```

(Authelia's `database_index` is 0 unless you set it. For another number, add `+select` to the rules:
the configurator must choose that database when it connects. `+select` cannot write anything.)

It can list, read and delete the session keys, and **nothing else**: it cannot create a session, so
it cannot sign anyone in, and it cannot read other keys. Checked in the tests against a real Redis:
`SET` and reading other keys are refused. Your own `default` user keeps its password.

## How it works

Authelia keeps each session as a key `authelia-session:<random id>` whose value is encrypted with
your `session.secret` (AES-256-GCM). There is no index by user, so the configurator reads every
session key, decrypts it with the secret and groups them by the username inside. The browser's
cookie value is the same id, which is how it knows which session is yours.

Rules it keeps (they are in the code's header, and tested):

- It only **scans, reads and deletes**. It never creates or changes a session.
- Of a decrypted session it keeps a handful of fields. A session can hold a pending authenticator
  secret while someone sets up 2FA; that is never read into an object, logged or shown.
- A session id is a live login, so **no id is ever shown, put in a URL or logged**. Each session
  gets an opaque handle (a keyed hash of the id) for the buttons; it cannot be used to sign in, and
  it only ever ends a session of the user whose page it was posted from.
- Anything unexpected is shown as a message and **deletes nothing**: Redis down, a wrong secret, a
  format it does not recognise. Keys it cannot read are never touched.
- Every sign-out is **recorded** in the audit log (who, which user, how many; never a key) and sent
  to the notification webhook if you set one.
- Reads are bounded (50 000 keys, 3 seconds) and cached for 5 seconds. After a failure it answers
  "unavailable" at once for 15 seconds, so a Redis outage does not slow every page.

## If something is wrong

The editor's *Open sessions* block says what the problem is. The Overview then shows a "needs
attention" item too.

| Message | Meaning and fix |
|---|---|
| Open sessions are not set up | The two settings are not set (the add-on file is not in the command, or the container was not recreated). |
| the session secret file does not exist | The file is not mounted at `SESSIONS_SECRET_FILE`: check the `volumes:` line, and run `docker compose up -d` after editing it (a restart does not pick up new volumes). |
| `SESSIONS_SECRET_FILE` is a folder | Docker creates a folder when the host file did not exist at start. Remove it, create the file, `docker compose up -d --force-recreate configurator`. |
| the session secret file is not readable by the configurator's user | Fix the owner and mode (step 1). On SELinux systems (Fedora, RHEL) add `,z` to the mount: `...:/run/secrets/session_secret:ro,z`. |
| the session secret file is empty | Step 1 wrote nothing. |
| Redis cannot be reached | The configurator is not on the Redis network, or Redis is down. |
| Redis refused the configurator's login | `CONFIGURATOR_REDIS_PASSWORD` differs from what Redis started with: recreate `redis` after changing it. |
| the Redis user may not read or delete the session keys | The `--user` line was changed or is not applied yet (check `docker exec <redis> redis-cli ACL USERS` lists `configurator`), or Authelia's `database_index` is not 0 (add `+select`). |
| None of the sessions could be read | `SESSIONS_SECRET_FILE` is not Authelia's `session.secret` (same bytes, no extra text), or Authelia changed its format. |
| The list may be incomplete | More than 50 000 session keys, or Redis answered slowly. |

To see what the container itself sees:

```sh
docker compose exec configurator sh -c 'id; echo "$SESSIONS_SECRET_FILE"; ls -lnd "$SESSIONS_SECRET_FILE"; wc -c < "$SESSIONS_SECRET_FILE"'
```

## Limits

- **Single Redis only.** Redis Sentinel and cluster setups are not covered.
- **OpenID Connect apps keep their own sign-in.** Ending the Authelia session makes every site
  behind Authelia ask for a login again. An app that signed the user in through OIDC (Grafana,
  Nextcloud...) keeps its own cookie until it expires or checks again; revoking those is up to the
  app.
- **It relies on Authelia's internal session format.** It is checked against the pinned Authelia
  version in CI (`tests/integration/test_sessions_redis.py`), so a format change fails the build
  before a release. If a future Authelia changes it, you see "None of the sessions could be read"
  and nothing is deleted.

## Turning it off

Start without the add-on file: `docker compose -f compose.yml up -d`. The Redis user disappears with
the command line that created it. You can delete `secrets/session_secret`.
