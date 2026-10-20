#!/usr/bin/env bash
# Builds local/crowdsec-firewall-bouncer:<VERSION> from CrowdSec's official release binary.
# Run it on the server that will use the image (it checks the host's iptables backend):
#
#   ./build.bash
#
# Upgrading: set VERSION and both checksums (docs/firewall-bouncer.md, "Updating"), run this,
# then change the image tag in compose.firewall-bouncer.yml and `docker compose up -d`.
set -euo pipefail

VERSION="v0.0.38"
# sha256 of crowdsec-firewall-bouncer-linux-<arch>.tgz of that release
case "$(uname -m)" in
  x86_64) ARCH=amd64 SHA256="3cb7ca302438ede690849218d585dee6cbba7915982f79f3dd45024a9eced31e" ;;
  aarch64 | arm64) ARCH=arm64 SHA256="5da2f17c05d042748fbc8eed9b8c3dfaeeac571c81b087a600fa2ba226c2116c" ;;
  *) echo "unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac
IMAGE="local/crowdsec-firewall-bouncer:${VERSION}"

cd "$(dirname "$0")"
docker build --pull \
  --build-arg VERSION="$VERSION" --build-arg ARCH="$ARCH" --build-arg SHA256="$SHA256" \
  -t "$IMAGE" .

backend() { grep -oE '\((nf_tables|legacy)\)' <<<"$1" || echo "(unknown)"; }
inside="$(docker run --rm --entrypoint iptables "$IMAGE" -V)"
host="$(iptables -V 2>/dev/null || true)"

echo "image:    $IMAGE"
echo "bouncer:  $(docker run --rm --entrypoint crowdsec-firewall-bouncer "$IMAGE" -version 2>&1 | head -1)"
echo "iptables: image $inside | host ${host:-not found}"
if [ -n "$host" ] && [ "$(backend "$inside")" != "$(backend "$host")" ]; then
  echo "iptables backend differs between the image and the host: the rules would not apply." >&2
  exit 1
fi
