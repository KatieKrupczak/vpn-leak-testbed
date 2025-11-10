FROM ubuntu:24.04

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install OpenVPN, WireGuard, and basic networking tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    openvpn \
    wireguard \
    iproute2 \
    iptables \
    iputils-ping \
    dnsutils \
    curl \
    ca-certificates && \
  apt-get clean && rm -rf /var/lib/apt/lists/*

# Create Directory for VPN configurations
RUN mkdir -p /etc/vpn/configs
WORKDIR /etc/vpn/configs

# Copy start script
COPY start.sh /usr/local/bin/start-vpn
RUN chmod +x /usr/local/bin/start-vpn

# Default command
CMD ["/usr/local/bin/start-vpn"]