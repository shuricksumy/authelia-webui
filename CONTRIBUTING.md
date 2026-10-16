# Contributing

Read [SPEC.md](SPEC.md) first; it is the source of truth. Work is split into phases that are
reviewed one at a time.

## Public repository rules

Never commit real domains, hostnames, IPs, emails, usernames, secrets, password hashes, OIDC
client IDs/secrets, keys or certificates. Use `example.com`, `*.example.test`, RFC 5737
(`192.0.2.0/24`) and RFC 1918 ranges, and fake users (`alice`, `bob`). Test secrets, hashes and
keys are generated at test time into the gitignored `tests/fixtures/generated/`.

`make lint` includes a hygiene check that rejects hash-like strings, PEM blocks, non-example
domains and public IPs. Install the hooks with `pre-commit install`.

## Before opening a PR

```sh
make lint test test-integration test-e2e
make scan
```

- Integration tests use a real Authelia container at the pinned version. Never mock
  `authelia config validate`.
- Hashing and randomness always go through the bundled `authelia` binary.
- UI changes include updated screenshots (`make screenshots`) in the PR description.
