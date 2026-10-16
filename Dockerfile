# syntax=docker/dockerfile:1
# Single source of truth for the Authelia version: updated by Renovate / authelia-watch.yml.
ARG AUTHELIA_VERSION=4.39.28

FROM authelia/authelia:${AUTHELIA_VERSION} AS authelia

FROM python:3.13-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Debian (glibc), not Alpine: the Authelia release binary is dynamically linked against glibc.
FROM python:3.13-slim AS runtime
ARG AUTHELIA_VERSION
LABEL org.opencontainers.image.title="Authelia Configurator" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.authelia-version="${AUTHELIA_VERSION}"
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin app
COPY --from=authelia /app/authelia /usr/local/bin/authelia
# Fail the build if the bundled binary is not the pinned version.
RUN authelia --version | grep -F "${AUTHELIA_VERSION}"
COPY --from=builder /opt/venv /opt/venv
COPY app /srv/app
# The migration script (docs/migration.md): python -m scripts.split_config --config ... --out ...
COPY scripts/__init__.py scripts/split_config.py /srv/scripts/
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    AUTHELIA_VERSION=${AUTHELIA_VERSION}
WORKDIR /srv
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()==b'ok' else 1)"
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--no-server-header", "--no-proxy-headers"]
