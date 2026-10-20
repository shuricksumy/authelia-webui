# CrowdSec firewall bouncer, built from CrowdSec's official release binary (docs/firewall-bouncer.md).
# Build it with build.bash: it passes the pinned VERSION, the CPU (ARCH) and the archive's SHA256.
FROM debian:12-slim

ARG VERSION
ARG ARCH=amd64
ARG SHA256

# Debian 12's iptables uses the nf_tables backend, like current Debian/Ubuntu hosts; build.bash
# refuses to finish when the host uses the other one (rules would land where the kernel ignores them).
RUN test -n "$VERSION" && test -n "$SHA256" \
 && apt-get update \
 && apt-get install -y --no-install-recommends iptables ipset ca-certificates curl \
 && curl -fsSL -o /tmp/bouncer.tgz \
    "https://github.com/crowdsecurity/cs-firewall-bouncer/releases/download/${VERSION}/crowdsec-firewall-bouncer-linux-${ARCH}.tgz" \
 && echo "${SHA256}  /tmp/bouncer.tgz" | sha256sum -c - \
 && tar -xzf /tmp/bouncer.tgz -C /tmp \
 && install -m 755 "/tmp/crowdsec-firewall-bouncer-${VERSION}/crowdsec-firewall-bouncer" /usr/local/bin/ \
 && apt-get purge -y curl && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* /tmp/*

ENTRYPOINT ["/usr/local/bin/crowdsec-firewall-bouncer", "-c", "/etc/crowdsec-firewall-bouncer.yaml"]
