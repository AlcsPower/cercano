#!/usr/bin/env bash
# Comprueba que LICENSE es el texto oficial de AGPL-3.0 (bloqueo B-001).
# Uso: tools/check-license.sh [ruta-a-LICENSE]
set -euo pipefail

file="${1:-$(git rev-parse --show-toplevel)/LICENSE}"

if [[ ! -f "$file" ]]; then
  echo "ERROR: no existe $file" >&2
  exit 1
fi

if ! grep -q "GNU AFFERO GENERAL PUBLIC LICENSE" "$file" || ! grep -q "Version 3, 19 November 2007" "$file"; then
  echo "ERROR: $file no es el texto oficial de AGPL-3.0 (ver docs/status/BLOCKERS.md, B-001)." >&2
  exit 1
fi

lines=$(wc -l < "$file")
if (( lines < 600 )); then
  echo "ERROR: $file parece truncado ($lines líneas; el texto oficial tiene unas 660)." >&2
  exit 1
fi

echo "OK: $file contiene AGPL-3.0 ($lines líneas)."
