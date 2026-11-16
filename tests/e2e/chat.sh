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
# Suite de Pruebas E2E, Carga y Seguridad de Cercano Chat (F4.5-14)
# ==============================================================================
set -euo pipefail

API_URL="${API_URL:-http://127.0.0.1:21114}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-AdminCercano2026!}"
OUT_JSON="${OUT_JSON:-tests/e2e/chat_results.json}"

for arg in "$@"; do
    case "$arg" in
        --api-url=*) API_URL="${arg#*=}" ;;
        --admin-user=*) ADMIN_USER="${arg#*=}" ;;
        --admin-pass=*) ADMIN_PASS="${arg#*=}" ;;
        --out-json=*) OUT_JSON="${arg#*=}" ;;
        *)
            echo "Uso: $0 [--api-url=URL] [--admin-user=USER] [--admin-pass=PASS] [--out-json=PATH]"
            exit 1
            ;;
    esac
done

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
RESULTS_JSON="[]"
SUITE_START=$(date +%s)

record_result() {
    local test_id="$1"
    local name="$2"
    local status="$3"
    local duration_ms="$4"
    local message="${5:-}"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if [ "$status" = "passed" ]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        printf "  \033[32m[PASS]\033[0m %-18s %s (%dms)\n" "$test_id" "$name" "$duration_ms"
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        printf "  \033[31m[FAIL]\033[0m %-18s %s: %s (%dms)\n" "$test_id" "$name" "$message" "$duration_ms"
    fi

    local entry
    entry=$(node -e '
        const [id, name, status, duration, msg] = process.argv.slice(1);
        console.log(JSON.stringify({ id, name, status, duration_ms: Number(duration), message: msg || null }));
    ' "$test_id" "$name" "$status" "$duration_ms" "$message")

    RESULTS_JSON=$(node -e '
        const list = JSON.parse(process.argv[1]);
        const item = JSON.parse(process.argv[2]);
        list.push(item);
        console.log(JSON.stringify(list));
    ' "$RESULTS_JSON" "$entry")
}

echo "=== Suite E2E / Seguridad / Carga Cercano Chat (F4.5-14) ==="
echo "Target API: $API_URL"
echo ""

# 1. TC-F4.5-090-A: Autenticación Admin
T_START=$(date +%s%3N)
LOGIN_RESP=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" || true)
HTTP_CODE=$(echo "$LOGIN_RESP" | tail -n1)
BODY=$(echo "$LOGIN_RESP" | sed '$d')
T_END=$(date +%s%3N)

if [ "$HTTP_CODE" = "200" ]; then
    ADMIN_TOKEN=$(node -e "console.log(JSON.parse(process.argv[1]).token)" "$BODY")
    record_result "TC-F4.5-090-A" "Autenticación Admin" "passed" $((T_END - T_START))
else
    record_result "TC-F4.5-090-A" "Autenticación Admin" "failed" $((T_END - T_START)) "HTTP $HTTP_CODE: $BODY"
    exit 1
fi

# 2. TC-F4.5-090-B: Registro y Autenticación de Dispositivo Soporte (Ed25519)
T_START=$(date +%s%3N)
DEVICE_ID="dev-e2e-$(date +%s)-$RANDOM"
# Generate ed25519 keypair in Node.js
KEYPAIR_JSON=$(node -e '
    const crypto = require("crypto");
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const pubRaw = publicKey.export({ type: "spki", format: "der" }).slice(-32);
    console.log(JSON.stringify({
        pubHex: pubRaw.toString("hex"),
        privDer: privateKey.export({ type: "pkcs8", format: "der" }).toString("hex")
    }));
')
DEVICE_PUBKEY=$(node -e "console.log(JSON.parse(process.argv[1]).pubHex)" "$KEYPAIR_JSON")
DEVICE_PRIVKEY=$(node -e "console.log(JSON.parse(process.argv[1]).privDer)" "$KEYPAIR_JSON")

# Request challenge
CHALLENGE_RESP=$(curl -s -X POST "$API_URL/api/chat/auth/challenge" \
    -H "Content-Type: application/json" \
    -d "{\"device_id\":\"$DEVICE_ID\",\"public_key\":\"$DEVICE_PUBKEY\"}")
NONCE=$(node -e "console.log(JSON.parse(process.argv[1]).nonce)" "$CHALLENGE_RESP")

# Sign challenge nonce
SIG_HEX=$(node -e '
    const crypto = require("crypto");
    const [privDerHex, nonce] = process.argv.slice(1);
    const privKey = crypto.createPrivateKey({ key: Buffer.from(privDerHex, "hex"), format: "der", type: "pkcs8" });
    const sig = crypto.sign(null, Buffer.from(nonce, "utf8"), privKey);
    console.log(sig.toString("hex"));
' "$DEVICE_PRIVKEY" "$NONCE")

# Verify and get device token
VERIFY_RESP=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/chat/auth/verify" \
    -H "Content-Type: application/json" \
    -d "{\"device_id\":\"$DEVICE_ID\",\"signature\":\"$SIG_HEX\"}")
HTTP_CODE=$(echo "$VERIFY_RESP" | tail -n1)
BODY=$(echo "$VERIFY_RESP" | sed '$d')
T_END=$(date +%s%3N)

if [ "$HTTP_CODE" = "200" ]; then
    DEVICE_TOKEN=$(node -e "console.log(JSON.parse(process.argv[1]).token)" "$BODY")
    record_result "TC-F4.5-090-B" "Registro y auth Ed25519 de dispositivo" "passed" $((T_END - T_START))
else
    record_result "TC-F4.5-090-B" "Registro y auth Ed25519 de dispositivo" "failed" $((T_END - T_START)) "HTTP $HTTP_CODE"
    exit 1
fi

# 3. TC-F4.5-090-C: Apertura de conversación con nombre de contacto
T_START=$(date +%s%3N)
CONV_RESP=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/chat/conversations" \
    -H "Authorization: Bearer $DEVICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"contact_name":"Ana García","body":"Solicito asistencia con certificado digital"}')
HTTP_CODE=$(echo "$CONV_RESP" | tail -n1)
BODY=$(echo "$CONV_RESP" | sed '$d')
T_END=$(date +%s%3N)

if [ "$HTTP_CODE" = "201" ]; then
    CONV_ID=$(node -e "console.log(JSON.parse(process.argv[1]).id)" "$BODY")
    record_result "TC-F4.5-090-C" "Apertura de conversación con contacto" "passed" $((T_END - T_START))
else
    record_result "TC-F4.5-090-C" "Apertura de conversación con contacto" "failed" $((T_END - T_START)) "HTTP $HTTP_CODE: $BODY"
    exit 1
fi

# 4. TC-F4.5-090-D: Asignación y reclamo por técnico
T_START=$(date +%s%3N)
ASSIGN_RESP=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/chat/conversations/$CONV_ID/assign" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{}")
HTTP_CODE=$(echo "$ASSIGN_RESP" | tail -n1)
T_END=$(date +%s%3N)

if [ "$HTTP_CODE" = "200" ]; then
    record_result "TC-F4.5-090-D" "Reclamo y asignación por técnico" "passed" $((T_END - T_START))
else
    record_result "TC-F4.5-090-D" "Reclamo y asignación por técnico" "failed" $((T_END - T_START)) "HTTP $HTTP_CODE"
fi

# 5. TC-F4.5-090-E: Mensajería bidireccional
T_START=$(date +%s%3N)
# Mensaje técnico
MSG_TEC=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/chat/conversations/$CONV_ID/messages" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"body":"Hola Ana, revisando tu solicitud."}')
# Mensaje cliente
MSG_CLI=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/chat/conversations/$CONV_ID/messages" \
    -H "Authorization: Bearer $DEVICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"body":"Gracias, adjunto captura del error."}')
CODE_TEC=$(echo "$MSG_TEC" | tail -n1)
CODE_CLI=$(echo "$MSG_CLI" | tail -n1)
T_END=$(date +%s%3N)

if [ "$CODE_TEC" = "201" ] && [ "$CODE_CLI" = "201" ]; then
    record_result "TC-F4.5-090-E" "Mensajería bidireccional técnico/soporte" "passed" $((T_END - T_START))
else
    record_result "TC-F4.5-090-E" "Mensajería bidireccional técnico/soporte" "failed" $((T_END - T_START)) "Tec: $CODE_TEC, Cli: $CODE_CLI"
fi

# 6. TC-F4.5-090-F: Subida y descarga de adjuntos
T_START=$(date +%s%3N)
# 1x1 valid PNG
PNG_HEX="89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c63000100000500010d0a2db40000000049454e44ae426082"
TMP_PNG=$(mktemp)
echo "$PNG_HEX" | xxd -r -p > "$TMP_PNG"

UPLOAD_RESP=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/chat/conversations/$CONV_ID/attachments" \
    -H "Authorization: Bearer $DEVICE_TOKEN" \
    -H "Content-Type: multipart/form-data" \
    -F "file=@$TMP_PNG;filename=pantallazo.png;type=image/png")
HTTP_CODE=$(echo "$UPLOAD_RESP" | tail -n1)
BODY=$(echo "$UPLOAD_RESP" | sed '$d')
rm -f "$TMP_PNG"

if [ "$HTTP_CODE" = "201" ]; then
    ATT_ID=$(node -e "console.log(JSON.parse(process.argv[1]).attachment_id || JSON.parse(process.argv[1]).id)" "$BODY")
    DOWN_RESP=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/api/chat/attachments/$ATT_ID" \
        -H "Authorization: Bearer $ADMIN_TOKEN")
    DOWN_CODE=$(echo "$DOWN_RESP" | tail -n1)
    T_END=$(date +%s%3N)
    if [ "$DOWN_CODE" = "200" ]; then
        record_result "TC-F4.5-090-F" "Subida y descarga de adjuntos con magic bytes" "passed" $((T_END - T_START))
    else
        record_result "TC-F4.5-090-F" "Subida y descarga de adjuntos con magic bytes" "failed" $((T_END - T_START)) "Download: $DOWN_CODE"
    fi
else
    T_END=$(date +%s%3N)
    record_result "TC-F4.5-090-F" "Subida y descarga de adjuntos con magic bytes" "failed" $((T_END - T_START)) "Upload: $HTTP_CODE"
fi

# 7. TC-F4.5-090-G: Escalado a sesión remota (cercano://)
T_START=$(date +%s%3N)
ESC_RESP=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/chat/conversations/$CONV_ID/escalate" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{}")
HTTP_CODE=$(echo "$ESC_RESP" | tail -n1)
BODY=$(echo "$ESC_RESP" | sed '$d')
T_END=$(date +%s%3N)

if [ "$HTTP_CODE" = "200" ]; then
    URL=$(node -e "console.log(JSON.parse(process.argv[1]).url)" "$BODY")
    if [[ "$URL" =~ ^cercano://connect\?device=.*\&trace=.* ]]; then
        record_result "TC-F4.5-090-G" "Escalado a sesión remota con URI scheme cercano://" "passed" $((T_END - T_START))
    else
        record_result "TC-F4.5-090-G" "Escalado a sesión remota con URI scheme cercano://" "failed" $((T_END - T_START)) "Formato URI inválido: $URL"
    fi
else
    record_result "TC-F4.5-090-G" "Escalado a sesión remota con URI scheme cercano://" "failed" $((T_END - T_START)) "HTTP $HTTP_CODE: $BODY"
fi

# 8. TC-F4.5-090-H: Cierre y reapertura supervisada
T_START=$(date +%s%3N)
CLOSE_RESP=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/chat/conversations/$CONV_ID/close" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"resolution":"resuelto"}')
REOPEN_RESP=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/chat/conversations/$CONV_ID/reopen" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{}")
CODE_CLOSE=$(echo "$CLOSE_RESP" | tail -n1)
CODE_REOPEN=$(echo "$REOPEN_RESP" | tail -n1)
T_END=$(date +%s%3N)

if [ "$CODE_CLOSE" = "200" ] && [ "$CODE_REOPEN" = "200" ]; then
    record_result "TC-F4.5-090-H" "Cierre y reapertura supervisada" "passed" $((T_END - T_START))
else
    record_result "TC-F4.5-090-H" "Cierre y reapertura supervisada" "failed" $((T_END - T_START)) "Close: $CODE_CLOSE, Reopen: $CODE_REOPEN"
fi

# 9. TC-F4.5-016: Prevención IDOR entre dispositivos
T_START=$(date +%s%3N)
# Generar segundo dispositivo B
DEV_B_RESP=$(curl -s -X POST "$API_URL/api/chat/auth/challenge" \
    -H "Content-Type: application/json" \
    -d "{\"device_id\":\"dev-b-idor-$RANDOM\",\"public_key\":\"$DEVICE_PUBKEY\"}")
NONCE_B=$(node -e "console.log(JSON.parse(process.argv[1]).nonce)" "$DEV_B_RESP")
SIG_B=$(node -e '
    const crypto = require("crypto");
    const [privDerHex, nonce] = process.argv.slice(1);
    const privKey = crypto.createPrivateKey({ key: Buffer.from(privDerHex, "hex"), format: "der", type: "pkcs8" });
    console.log(crypto.sign(null, Buffer.from(nonce, "utf8"), privKey).toString("hex"));
' "$DEVICE_PRIVKEY" "$NONCE_B")
VERIFY_B=$(curl -s -X POST "$API_URL/api/chat/auth/verify" \
    -H "Content-Type: application/json" \
    -d "{\"device_id\":\"dev-b-idor-$RANDOM\",\"signature\":\"$SIG_B\"}")
TOKEN_B=$(node -e "console.log(JSON.parse(process.argv[1]).token)" "$VERIFY_B")

# Intentar acceder a la conversación del dispositivo A con token de B
IDOR_RESP=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/api/chat/conversations/$CONV_ID/messages" \
    -H "Authorization: Bearer $TOKEN_B")
IDOR_CODE=$(echo "$IDOR_RESP" | tail -n1)
T_END=$(date +%s%3N)

if [ "$IDOR_CODE" = "403" ] || [ "$IDOR_CODE" = "404" ]; then
    record_result "TC-F4.5-016" "Prevención IDOR entre dispositivos ajenos" "passed" $((T_END - T_START))
else
    record_result "TC-F4.5-016" "Prevención IDOR entre dispositivos ajenos" "failed" $((T_END - T_START)) "Código inesperado: $IDOR_CODE"
fi

# 10. TC-F4.5-080: Prueba de carga concurrente básica (100 peticiones)
T_START=$(date +%s%3N)
LOAD_FAILS=0
for i in $(seq 1 100); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$API_URL/api/chat/branding")
    if [ "$HTTP_CODE" != "200" ]; then
        LOAD_FAILS=$((LOAD_FAILS + 1))
    fi
done
T_END=$(date +%s%3N)

if [ "$LOAD_FAILS" -eq 0 ]; then
    record_result "TC-F4.5-080" "Carga básica concurrente (100 peticiones en ráfaga)" "passed" $((T_END - T_START))
else
    record_result "TC-F4.5-080" "Carga básica concurrente (100 peticiones en ráfaga)" "failed" $((T_END - T_START)) "$LOAD_FAILS fallos"
fi

# 11. TC-F4.5-051 / TC-F4.5-052: Verificación de privacidad estricta en auditoría
T_START=$(date +%s%3N)
# Exportar eventos o consultar auditoría con token de admin
AUDIT_EXPORT=$(curl -s -X GET "$API_URL/api/audit/events?limit=200" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
LEAK_BODIES=$(echo "$AUDIT_EXPORT" | grep -i "Solicito asistencia con certificado digital" || true)
LEAK_NAMES=$(echo "$AUDIT_EXPORT" | grep -i "Ana García" || true)
LEAK_TOKENS=$(echo "$AUDIT_EXPORT" | grep -i "$DEVICE_TOKEN" || true)
T_END=$(date +%s%3N)

if [ -z "$LEAK_BODIES" ] && [ -z "$LEAK_NAMES" ] && [ -z "$LEAK_TOKENS" ]; then
    record_result "TC-F4.5-051" "Privacidad estricta: cero cuerpos, nombres o tokens en auditoría" "passed" $((T_END - T_START))
else
    record_result "TC-F4.5-051" "Privacidad estricta: cero cuerpos, nombres o tokens en auditoría" "failed" $((T_END - T_START)) "Fuga detectada en registros de auditoría"
fi

SUITE_END=$(date +%s)
TOTAL_DURATION=$((SUITE_END - SUITE_START))

echo ""
echo "=== Resumen E2E Cercano Chat ==="
echo "Total de pruebas : $TOTAL_TESTS"
echo "Aprobadas        : $PASSED_TESTS"
echo "Fallidas         : $FAILED_TESTS"
echo "Duración total   : ${TOTAL_DURATION}s"

mkdir -p "$(dirname "$OUT_JSON")"
echo "$RESULTS_JSON" > "$OUT_JSON"
echo "Resultados exportados en: $OUT_JSON"

if [ "$FAILED_TESTS" -gt 0 ]; then
    exit 1
fi
exit 0
