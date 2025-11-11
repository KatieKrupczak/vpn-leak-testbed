FROM debian:bullseye-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install Node.js + npm + Chromium + tcpdump + utilities
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

# Install Node.js LTS via nodesource
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - && \
    apt-get install -y nodejs && \
    npm install -g npm@latest && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /agent

# Copy scripts
COPY visit_urls.sh /agent/visit_urls.sh
COPY webrtc_check.js /agent/webrtc_check.js
RUN chmod +x /agent/visit_urls.sh

# Install puppeteer-core (controls system Chromium)
RUN npm init -y && npm install puppeteer-core

WORKDIR /results
CMD ["bash"]
