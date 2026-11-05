FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    netcat-openbsd \
    iproute2 \
    curl \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/cercano
COPY entrypoint.sh /opt/cercano/entrypoint.sh
RUN chmod +x /opt/cercano/entrypoint.sh

EXPOSE 21115/tcp 21116/tcp 21116/udp 21117/tcp 21118/tcp 21119/tcp
ENTRYPOINT ["/opt/cercano/entrypoint.sh"]
