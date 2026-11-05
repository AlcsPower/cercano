#!/usr/bin/env bash
# Copyright (C) 2026 Cercano Contributors
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail

echo "=== Cercano Server Mock / Runner ==="

# Si existen binarios compilados en /opt/cercano/bin, ejecutarlos
if [[ -x "/opt/cercano/bin/hbbs" && -x "/opt/cercano/bin/hbbr" ]]; then
  echo "Ejecutando binarios reales de Cercano Server..."
  /opt/cercano/bin/hbbr &
  exec /opt/cercano/bin/hbbs -r localhost
fi

echo "Binarios reales no encontrados en /opt/cercano/bin (F0-02/F0-04 pendiente)."
echo "Iniciando listeners mock en puertos estándar (21115, 21116, 21117)..."

# Mock TCP listeners usando nc en background
nc -l -k -p 21115 &
nc -l -k -p 21116 &
nc -l -k -p 21117 &

echo "Servidor de pruebas listo en puertos 21115-21117."
wait -n
