FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        tcpdump \
        procps \
        iproute2 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /results

COPY visit_urls.sh /agent/visit_urls.sh
RUN chmod +x /agent/visit_urls.sh

CMD ["bash"]


