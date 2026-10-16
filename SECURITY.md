# Security policy

This tool manages access control for your services, so security reports are welcome.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** (the repository's *Security* tab,
*Report a vulnerability*). Do not open a public issue for security problems, and do not include real
domains, secrets or configuration in a report: a minimal synthetic reproduction is enough.

We aim to acknowledge a report within a few days and to fix confirmed issues before any public disclosure.

## Scope

In scope: authentication/authorisation bypass of the admin UI (client IP and header trust, CSRF,
sessions), leaking secrets into files, logs, git or HTML, bypassing protected rules, command
injection through the Authelia CLI wrapper, and weaknesses in the container or release pipeline.

Out of scope: exposing the tool to the public internet against the documented guidance, and
vulnerabilities in Authelia itself (report those to the Authelia project).

## Supported versions

Only the latest release, built against the latest Authelia release it was tested with.
