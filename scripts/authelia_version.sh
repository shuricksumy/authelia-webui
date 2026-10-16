#!/bin/sh
# Print the pinned Authelia version (Dockerfile ARG is the single source of truth).
sed -n 's/^ARG AUTHELIA_VERSION=//p' "$(dirname "$0")/../Dockerfile" | head -n1
