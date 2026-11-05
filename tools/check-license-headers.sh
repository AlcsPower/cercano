#!/usr/bin/env bash
# Comprueba que los archivos de código fuente nuevos contengan el encabezado de licencia AGPL-3.0.
# Regla AGENTS.md §6. Ignora vendor/, docs/, branding/ y archivos de configuración.
set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT_DIR"

missing=0

# Buscar archivos .rs rastreados en git fuera de vendor/
while IFS= read -r file; do
  if [[ -n "$file" && -f "$file" ]]; then
    if ! grep -q "AGPL-3.0" "$file"; then
      echo "ERROR: $file no contiene el encabezado AGPL-3.0 requerido." >&2
      missing=$((missing + 1))
    fi
  fi
done < <(git ls-files "*.rs" ':!:vendor/**' 2>/dev/null || true)

if (( missing > 0 )); then
  echo "ERROR: Se encontraron $missing archivo(s) sin encabezado de licencia AGPL-3.0." >&2
  exit 1
fi

echo "OK: Todos los archivos de código fuente verificados tienen el encabezado AGPL-3.0."
