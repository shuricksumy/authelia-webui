# Emergency access: reaching the configurator when Authelia is down

The configurator normally sits behind Authelia. When Authelia is the thing that is broken (a bad
configuration, an expired certificate, a container that will not start) the usual URL does not
work, and that is exactly when you need the Logs, History and apply pages. The emergency door
is a second port on the configurator that does not use Authelia.

It is **off by default**. Turn it on once, while everything works.

## Set it up

1. Make a password and its digest with the Authelia binary (the password is shown once; store it
   in your password manager):

   ```sh
   docker run --rm authelia/authelia:4.39.28 authelia crypto hash generate argon2 --random \
       --random.length 32 --random.charset alphanumeric
   ```

   Keep the `Random Password` in your password manager; use the `Digest` below.
2. In the compose `.env` set both values (single quotes keep the `$` signs literal):

   ```sh
   EMERGENCY_PORT=8090
   EMERGENCY_PASSWORD_HASH='$argon2id$v=19$m=65536,t=3,p=4$...'
   ```

   The configurator refuses to start with one of them but not the other.
3. `docker compose up -d`. The production compose file publishes the port as
   `127.0.0.1:8090:8090`: **only on the server's loopback address**. Never change that to
   `0.0.0.0` or put it behind Traefik: the only protection of this door is the password.

## Use it

```sh
ssh -L 8090:127.0.0.1:8090 you@your-server       # keep this open
```

Open <http://localhost:8090>, sign in with the emergency password. A red banner reminds you that
Authelia is not protecting the session. Everything works, in the order you will probably need it:

1. **Logs** to see why Authelia will not start (`log.file_path` must be configured).
2. **History**: the previous version of the rules or clients; "Revert to this" loads it into the
   draft, then review and apply as usual (the apply rolls back on its own if Authelia stays
   unhealthy). A broken main configuration file is not managed here: fix it on the host, then use
   **Re-validate** in the banner.
3. **Keys**: certificate expiry and the key files.
4. **Backup**: take one before you change anything.

Sign out when done (banner button). The session ends after 30 minutes without a request, and
after 2 hours at most.

## What protects it

- It listens on the container's interface but is published on the host's loopback only; the SSH
  login to the server is the real first factor.
- Only requests whose `Host` is `localhost:<port>` or `127.0.0.1:<port>` are answered: DNS
  rebinding and a proxy pointed at it get a 403.
- **5 wrong passwords lock the login for 15 minutes** (for everyone, and across restarts).
- The password is checked by the bundled Authelia binary; it never appears on a command line, in a
  log or in the audit log. Every attempt is audited (`emergency-login`); successes and lockouts
  send the webhook notification.
- The cookie is signed, `HttpOnly`, `SameSite=Strict`. It is the only cookie the app ever sets,
  and only on this port.

Anyone who can reach the port from the server itself (any local user, or another container on the
Docker network) can try passwords, five at a time: choose a long random one, and keep the
configurator off networks that hold untrusted containers.

## Rotating the password

Generate a new digest, replace `EMERGENCY_PASSWORD_HASH`, `docker compose up -d`. Old sessions
stay valid for their remaining time; restart the configurator (or change `APP_SECRET_KEY`) to end
them at once.

## Without the web door

The SSH recipe in the README (`git revert HEAD`, `docker restart authelia`) always works, with
or without this feature.
