FROM debian:bullseye-slim

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install OpenVPN, WireGuard, and basic networking tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    openvpn \
    wireguard \
    wireguard-tools \
    procps \
    iproute2 \
    iptables \
    iputils-ping \
    dnsutils \
    curl \
    ca-certificates && \
    # Provide a no-op resolvconf so wg-quick doesn't crash
    # (we won't use it to manage DNS in this setup)
  printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/resolvconf && \
  chmod +x /usr/local/bin/resolvconf && \
  apt-get clean && rm -rf /var/lib/apt/lists/*

# Create Directory for VPN configurations
RUN mkdir -p /etc/vpn/configs
WORKDIR /etc/vpn/configs

# Copy start script
COPY start.sh /usr/local/bin/start-vpn
RUN chmod +x /usr/local/bin/start-vpn

# Copy DNS helper script for configuring DNS for openvpn and testing connectivity
COPY vpn-dns-helper.sh /usr/local/bin/vpn-dns-helper.sh
RUN chmod +x /usr/local/bin/vpn-dns-helper.sh

# Copy dump state script for testing connectivity
COPY dump-state.sh /usr/local/bin/vpm-dump-state
RUN chmod +x /usr/local/bin/vpn-dump-state

# Default command
CMD ["/usr/local/bin/start-vpn"]