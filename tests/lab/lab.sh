#!/usr/bin/env bash
# Copyright (C) 2026 Cercano Contributors
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

action="${1:-help}"

case "$action" in
  up)
    echo "==> Levantando laboratorio LAN en Docker..."
    docker compose -f "$COMPOSE_FILE" up -d --build
    echo "==> Laboratorio activo."
    docker compose -f "$COMPOSE_FILE" ps
    ;;
  down)
    echo "==> Deteniendo laboratorio LAN..."
    docker compose -f "$COMPOSE_FILE" down -v
    echo "==> Laboratorio destruido."
    ;;
  status)
    docker compose -f "$COMPOSE_FILE" ps
    ;;
  logs)
    shift || true
    docker compose -f "$COMPOSE_FILE" logs "${@:---tail=50}"
    ;;
  smoke)
    echo "==> Verificando API Stub..."
    curl -fsS http://localhost:21114/healthz || exit 1
    echo ""
    echo "==> Verificando ping client-1 -> client-2..."
    docker exec cercano-client-linux-1 ping -c 2 172.28.0.22
    echo "==> Verificando puertos server desde client-1 (21115, 21116 TCP, 21117 TCP, 21116 UDP)..."
    docker exec cercano-client-linux-1 nc -z -v -w 2 172.28.0.11 21115
    docker exec cercano-client-linux-1 nc -z -v -w 2 172.28.0.11 21116
    docker exec cercano-client-linux-1 nc -z -v -w 2 172.28.0.11 21117
    docker exec cercano-client-linux-1 nc -z -v -u -w 2 172.28.0.11 21116
    echo "==> Smoke test OK."
    ;;
  netem)
    sub="${2:-help}"
    case "$sub" in
      latency)
        ms="${3:-100}"
        echo "==> Configurando latencia ${ms}ms en client-linux-1..."
        docker exec --privileged cercano-client-linux-1 tc qdisc del dev eth0 root 2>/dev/null || true
        docker exec --privileged cercano-client-linux-1 tc qdisc add dev eth0 root netem delay "${ms}ms"
        ;;
      drop-udp)
        echo "==> Bloqueando UDP directo client-1 -> client-2..."
        docker exec --privileged cercano-client-linux-1 iptables -F 2>/dev/null || true
        docker exec --privileged cercano-client-linux-1 iptables -A OUTPUT -p udp -d 172.28.0.22 -j DROP
        ;;
      reset)
        echo "==> Restableciendo reglas de red..."
        docker exec --privileged cercano-client-linux-1 tc qdisc del dev eth0 root 2>/dev/null || true
        docker exec --privileged cercano-client-linux-1 iptables -F 2>/dev/null || true
        ;;
      *)
        echo "Uso: ./lab.sh netem [latency <ms>|drop-udp|reset]"
        ;;
    esac
    ;;
  *)
    echo "Uso: ./lab.sh {up|down|status|logs|smoke|netem}"
    ;;
esac
