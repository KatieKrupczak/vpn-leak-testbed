FROM debian:bullseye-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install utilities + Node.js + Chromium + tcpdump
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      curl \
      gnupg \
      ca-certificates \
      tcpdump \
      jq \
      chromium \
      chromium-driver \
      procps \
      iproute2 \
      build-essential \
      python3 \
      git \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js LTS
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - && \
    apt-get install -y nodejs && \
    npm install -g npm@latest && \
    rm -rf /var/lib/apt/lists/*

# Set working directory for scripts
WORKDIR /agent

# Copy scripts
COPY visit_urls.sh webrtc_check.js quic_check.js /agent/

RUN chmod +x /agent/visit_urls.sh

# Install Puppeteer locally
RUN npm init -y && npm install puppeteer

# Default working directory for outputs
WORKDIR /results
CMD ["bash"]
