# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Single source of truth for the Authelia version: updated by Renovate / authelia-watch.yml.
ARG AUTHELIA_VERSION=4.39.28

FROM authelia/authelia:${AUTHELIA_VERSION} AS authelia

FROM python:3.13-slim@sha256:57b29a7c050c4e679e4bea572e14b3965cf4b5839de2da49d55e49ffc4024f39 AS builder
COPY --from=ghcr.io/astral-sh/uv:0.13@sha256:9f130421e930bfbdc563c00740466603f8723158e90297d07957c2294640262b /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Debian (glibc), not Alpine: the Authelia release binary is dynamically linked against glibc.
FROM python:3.13-slim@sha256:57b29a7c050c4e679e4bea572e14b3965cf4b5839de2da49d55e49ffc4024f39 AS runtime
ARG AUTHELIA_VERSION
LABEL org.opencontainers.image.title="Authelia Configurator" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.authelia-version="${AUTHELIA_VERSION}"
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin app
# pip is not needed at run time (the virtualenv comes from the builder), and the base image's pip
# carries its own vendored copy of certifi, which a scanner flags whenever certifi has an advisory
# that the pip release in the base image has not caught up with yet. Less to patch, smaller image.
RUN python -m pip uninstall -y pip
COPY --from=authelia /app/authelia /usr/local/bin/authelia
# Fail the build if the bundled binary is not the pinned version.
RUN authelia --version | grep -F "${AUTHELIA_VERSION}"
COPY --from=builder /opt/venv /opt/venv
COPY app /srv/app
# The migration scripts, run with `docker run ... python -m scripts.<name>`:
# split_config (docs/migration.md) and migrate_jwks (the one-time key move, docs/jwks.md).
COPY scripts/__init__.py scripts/split_config.py scripts/migrate_jwks.py /srv/scripts/
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    AUTHELIA_VERSION=${AUTHELIA_VERSION}
WORKDIR /srv
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()==b'ok' else 1)"
# One server on 8080 and, when EMERGENCY_PORT is set, on that port too (app/serve.py).
CMD ["python", "-m", "app.serve"]
