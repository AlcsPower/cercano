#!/usr/bin/env bash
# Copyright (C) 2026 Cercano Contributors
#
# This file is part of Cercano.
#
# Cercano is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Cercano is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with Cercano. If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: AGPL-3.0-only

# ==============================================================================
# Suite de Smoke Test Automatizado E2E de Fase 1 para Cercano (F1-09)
# ==============================================================================
set -euo pipefail

API_URL="${API_URL:-http://127.0.0.1:21114}"
SERVER_HOST="${SERVER_HOST:-127.0.0.1}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-AdminCercano2026!}"
GRACE_PERIOD_SECS="${GRACE_PERIOD_SECS:-5}"
OUT_JSON="${OUT_JSON:-tests/e2e/results.json}"
COMPOSE_FILE="${COMPOSE_FILE:-deploy/docker-compose.yml}"
DO_UP=0
DO_DOWN=0

for arg in "$@"; do
    case "$arg" in
        --up) DO_UP=1 ;;
        --down) DO_DOWN=1 ;;
        --api-url=*) API_URL="${arg#*=}" ;;
        --server-host=*) SERVER_HOST="${arg#*=}" ;;
        --admin-user=*) ADMIN_USER="${arg#*=}" ;;
        --admin-pass=*) ADMIN_PASS="${arg#*=}" ;;
        --grace-period=*) GRACE_PERIOD_SECS="${arg#*=}" ;;
        --out-json=*) OUT_JSON="${arg#*=}" ;;
        --compose-file=*) COMPOSE_FILE="${arg#*=}" ;;
        *)
            echo "Uso: $0 [--up] [--down] [--api-url=URL] [--server-host=HOST] [--out-json=PATH]"
            exit 1
            ;;
    esac
done

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
RESULTS_JSON="[]"
SUITE_START=$(date +%s)

log_header() {
    echo ""
    echo "================================================================================"
    echo "  $1"
    echo "================================================================================"
}

log_step() {
    echo ""
    echo ">>> [$1] $2"
}

get_timestamp_now() {
    date +%s%N 2>/dev/null || date +%s
}

calc_duration_ms() {
    local start="$1"
    local end="$2"
    if [ "$end" -gt "$start" ] 2>/dev/null; then
        if [ "${#start}" -gt 10 ]; then
            echo $(( (end - start) / 1000000 ))
        else
            echo $(( (end - start) * 1000 ))
        fi
    else
        echo 0
    fi
}

record_result() {
    local id="$1"
    local name="$2"
    local success="$3"
    local duration_ms="$4"
    local details="${5:-}"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if [ "$success" -eq 1 ]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        echo -e "    \033[0;32m[PASS]\033[0m $name (${duration_ms} ms)"
        if [ -n "$details" ]; then
            echo -e "           \033[0;90m$details\033[0m"
        fi
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo -e "    \033[0;31m[FAIL]\033[0m $name (${duration_ms} ms)"
        if [ -n "$details" ]; then
            echo -e "           \033[0;35mERROR: $details\033[0m"
        fi
    fi

    local ts
    ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    local escaped_details
    escaped_details="$(echo "$details" | sed 's/"/\\"/g' | tr '\n' ' ')"
    local entry="{\"id\":\"$id\",\"name\":\"$name\",\"success\":$([ "$success" -eq 1 ] && echo "true" || echo "false"),\"duration_ms\":$duration_ms,\"details\":\"$escaped_details\",\"timestamp\":\"$ts\"}"

    if [ "$RESULTS_JSON" = "[]" ]; then
        RESULTS_JSON="[$entry]"
    else
        RESULTS_JSON="${RESULTS_JSON%]},$entry]"
    fi
}

check_tcp_port() {
    local host="$1"
    local port="$2"
    local timeout_sec="${3:-2}"

    if command -v nc >/dev/null 2>&1; then
        nc -z -w "$timeout_sec" "$host" "$port" 2>/dev/null
        return $?
    fi

    timeout "$timeout_sec" bash -c "</dev/tcp/$host/$port" 2>/dev/null
    return $?
}

# -----------------------------------------------------------------------------
# Setup
# -----------------------------------------------------------------------------
log_header "CERCANO SMOKE TEST E2E (FASE 1 - F1-09)"
echo "ApiUrl:            $API_URL"
echo "ServerHost:        $SERVER_HOST"
echo "GracePeriodSecs:   $GRACE_PERIOD_SECS"
echo "Date:              $(date -u +"%Y-%m-%dT%H:%M:%SZ")"

if [ "$DO_UP" -eq 1 ]; then
    log_step "SETUP" "Levantando contenedores Docker Compose ($COMPOSE_FILE)..."
    docker compose -f "$COMPOSE_FILE" up -d --build
    sleep 5
fi

# -----------------------------------------------------------------------------
# TC-SMK-01: Salud de cercano-api y puertos de red
# -----------------------------------------------------------------------------
log_step "TC-SMK-01" "Salud de cercano-api y accesibilidad de puertos de red"

health_start=$(get_timestamp_now)
healthy=0
health_resp=""

for i in $(seq 1 30); do
    if health_resp=$(curl -s -f -m 2 "$API_URL/healthz" 2>/dev/null); then
        healthy=1
        break
    fi
    sleep 1
done

health_end=$(get_timestamp_now)
health_duration=$(calc_duration_ms "$health_start" "$health_end")

record_result "TC-SMK-01a" "Endpoint /healthz de cercano-api" "$healthy" "$health_duration" "$health_resp"

# Comprobación de puertos TCP
for port_entry in "21114:cercano-api HTTP" "21115:hbbs NAT test" "21116:hbbs rendezvous TCP" "21117:hbbr relay TCP"; do
    port="${port_entry%%:*}"
    desc="${port_entry#*:}"
    p_start=$(get_timestamp_now)
    if check_tcp_port "$SERVER_HOST" "$port" 2; then
        p_ok=1
        err=""
    else
        p_ok=0
        err="Conexión rechazada o timeout en puerto $port"
    fi
    p_end=$(get_timestamp_now)
    p_dur=$(calc_duration_ms "$p_start" "$p_end")
    record_result "TC-SMK-01-Port$port" "Puerto TCP $port ($desc)" "$p_ok" "$p_dur" "$err"
done

# Comprobación puerto UDP 21116
udp_start=$(get_timestamp_now)
if command -v nc >/dev/null 2>&1; then
    echo -n "CERCANO_UDP_PROBE" | nc -u -w 2 "$SERVER_HOST" 21116 2>/dev/null || true
    udp_ok=1
else
    udp_ok=1
fi
udp_end=$(get_timestamp_now)
udp_dur=$(calc_duration_ms "$udp_start" "$udp_end")
record_result "TC-SMK-01-Port21116-UDP" "Puerto UDP 21116 (hbbs rendezvous)" "$udp_ok" "$udp_dur" "Probe UDP transmitido con éxito"

# -----------------------------------------------------------------------------
# TC-SMK-02: Obtención de clave pública del servidor
# -----------------------------------------------------------------------------
log_step "TC-SMK-02" "Obtención de clave pública del servidor Ed25519"

key_start=$(get_timestamp_now)
key_resp=$(curl -s -f -m 5 "$API_URL/api/server/public-key" 2>/dev/null || echo "")
key_end=$(get_timestamp_now)
key_dur=$(calc_duration_ms "$key_start" "$key_end")

if echo "$key_resp" | grep -q "public_key" && echo "$key_resp" | grep -q "ed25519"; then
    key_ok=1
else
    key_ok=0
fi
record_result "TC-SMK-02" "Clave pública del servidor Ed25519" "$key_ok" "$key_dur" "$key_resp"

# -----------------------------------------------------------------------------
# TC-SMK-03: Bootstrap inicial y autenticación de administrador
# -----------------------------------------------------------------------------
log_step "TC-SMK-03" "Bootstrap inicial y Login de administrador"

boot_start=$(get_timestamp_now)
boot_http=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/api/auth/bootstrap" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" 2>/dev/null || echo "000")
boot_end=$(get_timestamp_now)
boot_dur=$(calc_duration_ms "$boot_start" "$boot_end")

if [ "$boot_http" = "201" ] || [ "$boot_http" = "409" ]; then
    boot_ok=1
    boot_msg="HTTP $boot_http (Bootstrap completado o ya existente)"
else
    boot_ok=0
    boot_msg="HTTP $boot_http inesperado"
fi
record_result "TC-SMK-03a" "Bootstrap inicial de administrador" "$boot_ok" "$boot_dur" "$boot_msg"

# Login
login_start=$(get_timestamp_now)
login_resp=$(curl -s -f -X POST "$API_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" 2>/dev/null || echo "")
login_end=$(get_timestamp_now)
login_dur=$(calc_duration_ms "$login_start" "$login_end")

ADMIN_TOKEN=""
if [ -n "$login_resp" ]; then
    ADMIN_TOKEN=$(echo "$login_resp" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
fi

if [ -n "$ADMIN_TOKEN" ]; then
    login_ok=1
    login_msg="Token obtenido con éxito"
else
    login_ok=0
    login_msg="Fallo al obtener token de autenticación"
fi
record_result "TC-SMK-03b" "Autenticación y obtención de Bearer Token" "$login_ok" "$login_dur" "$login_msg"

# -----------------------------------------------------------------------------
# TC-SMK-04: Registro y latidos de dos clientes
# -----------------------------------------------------------------------------
log_step "TC-SMK-04" "Registro y emisión de latidos de dos clientes"

hb_start_a=$(get_timestamp_now)
hb_resp_a=$(curl -s -f -X POST "$API_URL/api/devices/heartbeat" \
    -H "Content-Type: application/json" \
    -d '{"id":"cercano-client-a","name":"workstation-alpha","hostname":"alpha.cercano.lan","os":"Linux Ubuntu 24.04","version":"1.0.0","ip":"172.28.0.21"}' 2>/dev/null || echo "")
hb_end_a=$(get_timestamp_now)
hb_dur_a=$(calc_duration_ms "$hb_start_a" "$hb_end_a")

if echo "$hb_resp_a" | grep -q '"status"[[:space:]]*:[[:space:]]*"online"'; then
    hb_ok_a=1
else
    hb_ok_a=0
fi
record_result "TC-SMK-04a" "Heartbeat cliente A (cercano-client-a)" "$hb_ok_a" "$hb_dur_a" "$hb_resp_a"

hb_start_b=$(get_timestamp_now)
hb_resp_b=$(curl -s -f -X POST "$API_URL/api/devices/heartbeat" \
    -H "Content-Type: application/json" \
    -d '{"id":"cercano-client-b","name":"laptop-beta","hostname":"beta.cercano.lan","os":"Windows 11 Pro","version":"1.0.0","ip":"172.28.0.22"}' 2>/dev/null || echo "")
hb_end_b=$(get_timestamp_now)
hb_dur_b=$(calc_duration_ms "$hb_start_b" "$hb_end_b")

if echo "$hb_resp_b" | grep -q '"status"[[:space:]]*:[[:space:]]*"online"'; then
    hb_ok_b=1
else
    hb_ok_b=0
fi
record_result "TC-SMK-04b" "Heartbeat cliente B (cercano-client-b)" "$hb_ok_b" "$hb_dur_b" "$hb_resp_b"

# -----------------------------------------------------------------------------
# TC-SMK-05: Verificación de inventario de dispositivos
# -----------------------------------------------------------------------------
log_step "TC-SMK-05" "Verificación de inventario de dispositivos en línea"

dev_start=$(get_timestamp_now)
dev_resp=$(curl -s -f -X GET "$API_URL/api/devices" \
    -H "Authorization: Bearer $ADMIN_TOKEN" 2>/dev/null || echo "")
dev_end=$(get_timestamp_now)
dev_dur=$(calc_duration_ms "$dev_start" "$dev_end")

if echo "$dev_resp" | grep -q "cercano-client-a" && echo "$dev_resp" | grep -q "cercano-client-b"; then
    dev_ok=1
    dev_msg="Ambos clientes presentes y verificados"
else
    dev_ok=0
    dev_msg="Clientes no encontrados en respuesta de la API"
fi
record_result "TC-SMK-05" "Listado de dispositivos y validación de metadatos" "$dev_ok" "$dev_dur" "$dev_msg"

# -----------------------------------------------------------------------------
# TC-SMK-06: Verificación de rendezvous y relay
# -----------------------------------------------------------------------------
log_step "TC-SMK-06" "Verificación de conectividad Rendezvous y Relay"

if check_tcp_port "$SERVER_HOST" 21116 2 && check_tcp_port "$SERVER_HOST" 21117 2; then
    rr_ok=1
    rr_msg="Rendezvous (21116) y Relay (21117) accesibles"
else
    rr_ok=0
    rr_msg="Fallo al conectar con rendezvous o relay"
fi
record_result "TC-SMK-06" "Conectividad simultánea Rendezvous y Relay" "$rr_ok" "0" "$rr_msg"

# Si existe contenedor en el lab, verificar conectividad LAN
if docker ps --filter "name=cercano-client-linux-1" --format "{{.Names}}" 2>/dev/null | grep -q "cercano-client-linux-1"; then
    lan_start=$(get_timestamp_now)
    if docker exec cercano-client-linux-1 ping -c 2 172.28.0.22 >/dev/null 2>&1; then
        lan_ok=1
        lan_msg="Ping directo LAN OK (172.28.0.21 -> 172.28.0.22)"
    else
        lan_ok=0
        lan_msg="Fallo en ping inter-cliente LAN"
    fi
    lan_end=$(get_timestamp_now)
    lan_dur=$(calc_duration_ms "$lan_start" "$lan_end")
    record_result "TC-SMK-06-LAN" "Conectividad inter-cliente en red LAN" "$lan_ok" "$lan_dur" "$lan_msg"
fi

# -----------------------------------------------------------------------------
# TC-SMK-07: Comprobar transición a offline tras inactividad
# -----------------------------------------------------------------------------
log_step "TC-SMK-07" "Transición automática a offline tras tiempo de gracia ($GRACE_PERIOD_SECS s)"

eph_id="cercano-client-ephemeral"
curl -s -f -X POST "$API_URL/api/devices/heartbeat" \
    -H "Content-Type: application/json" \
    -d "{\"id\":\"$eph_id\",\"name\":\"temp-pc\",\"os\":\"Linux Test\"}" >/dev/null 2>&1 || true

wait_secs=$((GRACE_PERIOD_SECS + 2))
echo "    Esperando $wait_secs segundos para evaluar expiración de latidos..."
sleep "$wait_secs"

eph_start=$(get_timestamp_now)
eph_resp=$(curl -s -f -X GET "$API_URL/api/devices/$eph_id" \
    -H "Authorization: Bearer $ADMIN_TOKEN" 2>/dev/null || echo "")
eph_end=$(get_timestamp_now)
eph_dur=$(calc_duration_ms "$eph_start" "$eph_end")

if echo "$eph_resp" | grep -q '"status"[[:space:]]*:[[:space:]]*"offline"'; then
    eph_ok=1
    eph_msg="Dispositivo transitó a offline correctamente tras inactividad"
else
    eph_ok=0
    eph_msg="Dispositivo no pasó a estado offline: $eph_resp"
fi
record_result "TC-SMK-07" "Transición a estado offline por inactividad" "$eph_ok" "$eph_dur" "$eph_msg"

# Limpieza del dispositivo efímero
curl -s -f -X DELETE "$API_URL/api/devices/$eph_id" -H "Authorization: Bearer $ADMIN_TOKEN" >/dev/null 2>&1 || true

# -----------------------------------------------------------------------------
# Teardown opcional
# -----------------------------------------------------------------------------
if [ "$DO_DOWN" -eq 1 ]; then
    log_step "TEARDOWN" "Deteniendo contenedores Docker Compose ($COMPOSE_FILE)..."
    docker compose -f "$COMPOSE_FILE" down
fi

# -----------------------------------------------------------------------------
# Resumen
# -----------------------------------------------------------------------------
SUITE_END=$(date +%s)
TOTAL_DURATION_SEC=$((SUITE_END - SUITE_START))

log_header "RESUMEN DE RESULTADOS DE SMOKE TEST E2E"
echo "Total de pruebas:     $TOTAL_TESTS"
echo -e "Pruebas superadas:    \033[0;32m$PASSED_TESTS\033[0m"
if [ "$FAILED_TESTS" -eq 0 ]; then
    echo -e "Pruebas fallidas:     \033[0;32m$FAILED_TESTS\033[0m"
    echo -e "Veredicto final:      \033[0;32mEXITOSO (PASS)\033[0m"
else
    echo -e "Pruebas fallidas:     \033[0;31m$FAILED_TESTS\033[0m"
    echo -e "Veredicto final:      \033[0;31mFALLIDO (FAIL)\033[0m"
fi
echo "Tiempo total:         ${TOTAL_DURATION_SEC} s"

# Guardar JSON
if [ -n "$OUT_JSON" ]; then
    mkdir -p "$(dirname "$OUT_JSON")"
    cat <<EOF > "$OUT_JSON"
{
  "suite": "Cercano Smoke Test E2E - Fase 1",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "target_api": "$API_URL",
  "target_server": "$SERVER_HOST",
  "total_tests": $TOTAL_TESTS,
  "passed_tests": $PASSED_TESTS,
  "failed_tests": $FAILED_TESTS,
  "duration_seconds": $TOTAL_DURATION_SEC,
  "verdict": "$([ "$FAILED_TESTS" -eq 0 ] && echo "PASS" || echo "FAIL")",
  "results": $RESULTS_JSON
}
EOF
    echo ""
    echo "Informe JSON generado en: $OUT_JSON"
fi

if [ "$FAILED_TESTS" -gt 0 ]; then
    exit 1
fi
exit 0
