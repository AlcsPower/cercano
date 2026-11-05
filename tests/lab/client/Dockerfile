FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iptables \
    iputils-ping \
    curl \
    netcat-openbsd \
    dnsutils \
    procps \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
CMD ["tail", "-f", "/dev/null"]
