#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Cercano Contributors
#
# Script de compilación reproducible para el binario base de Cercano.
# Garantiza determinismo bit-a-bit conforme a AGENTS.md y PLAN-F3-GENERADOR (F3-03, TC-F3-021).

set -euo pipefail

# -----------------------------------------------------------------------------
# Detección de rutas y entorno
# -----------------------------------------------------------------------------
ROOT_DIR="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT_DIR"

# Asegurar que cargo esté en PATH (buscando en ubicaciones estándar de Rust si es necesario)
if ! command -v cargo &>/dev/null; then
  for candidate in "$HOME/.cargo/bin" /home/*/.cargo/bin /root/.cargo/bin; do
    if [[ -x "$candidate/cargo" ]]; then
      export PATH="$candidate:$PATH"
      break
    fi
  done
fi

if ! command -v cargo &>/dev/null; then
  echo "ERROR: 'cargo' no se encuentra en PATH. Instale Rust o ajuste PATH." >&2
  exit 1
fi

# -----------------------------------------------------------------------------
# Valores por defecto
# -----------------------------------------------------------------------------
MANIFEST_PATH=""
BIN_NAME=""
PACKAGE_NAME=""
TARGET_TRIPLE=""
OUT_DIR="$ROOT_DIR/dist/base"
PROFILE_PUBLIC_KEY=""
DO_VERIFY=0
DO_SBOM=0
DO_CLEAN=0

# -----------------------------------------------------------------------------
# Ayuda y parsing de argumentos
# -----------------------------------------------------------------------------
usage() {
  cat << 'EOF'
Uso: builder/build-base.sh [OPCIONES]

Opciones:
  --manifest-path <RUTA>    Ruta al Cargo.toml a compilar (defecto: vendor/client/Cargo.toml si existe)
  --bin <NOMBRE>            Nombre del binario a generar (defecto: cercano)
  --package <NOMBRE>        Nombre del paquete Cargo (defecto: detectado de Cargo.toml)
  --target <TRIPLE>         Target de compilación (ej. x86_64-unknown-linux-gnu)
  --out-dir <DIRECTORIO>    Directorio de salida para binarios y metadatos (defecto: dist/base)
  --profile-public-key <KEY> Clave pública Ed25519 en Base64 para CERCANO_PROFILE_PUBLIC_KEY
  --verify                  Compila dos veces en directorios target aislados y verifica
                            que las sumas SHA-256 sean idénticas (criterio TC-F3-021)
  --sbom                    Genera el archivo SBOM en formato SPDX 2.3 JSON
  --clean                   Limpia artefactos previos antes de compilar
  -h, --help                Muestra esta ayuda y termina

Variables de entorno deterministas:
  SOURCE_DATE_EPOCH         Timestamp Unix para timestamps en el binario y SBOM (defecto: commit de git)
  RUSTFLAGS                 Flags adicionales para el compilador Rust
  CARGO_INCREMENTAL         Forzado a 0 para garantizar reproducibilidad
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest-path)
      MANIFEST_PATH="$2"
      shift 2
      ;;
    --bin)
      BIN_NAME="$2"
      shift 2
      ;;
    --package)
      PACKAGE_NAME="$2"
      shift 2
      ;;
    --target)
      TARGET_TRIPLE="$2"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    --profile-public-key)
      PROFILE_PUBLIC_KEY="$2"
      shift 2
      ;;
    --verify)
      DO_VERIFY=1
      shift
      ;;
    --sbom)
      DO_SBOM=1
      shift
      ;;
    --clean)
      DO_CLEAN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: Opción desconocida: $1" >&2
      usage
      exit 1
      ;;
  esac
done

# Resolver manifest y nombres por defecto
if [[ -z "$MANIFEST_PATH" ]]; then
  if [[ -f "$ROOT_DIR/vendor/client/Cargo.toml" ]]; then
    MANIFEST_PATH="$ROOT_DIR/vendor/client/Cargo.toml"
    BIN_NAME="${BIN_NAME:-cercano}"
    PACKAGE_NAME="${PACKAGE_NAME:-cercano}"
  else
    MANIFEST_PATH="$ROOT_DIR/Cargo.toml"
  fi
fi

if [[ -z "$BIN_NAME" ]]; then
  BIN_NAME="cercano"
fi

# -----------------------------------------------------------------------------
# Configuración Determinista (Reproducible Builds)
# -----------------------------------------------------------------------------
# 1. SOURCE_DATE_EPOCH estándar de reproducible-builds.org
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  if git rev-parse --git-dir &>/dev/null; then
    SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct 2>/dev/null || date +%s)"
  else
    SOURCE_DATE_EPOCH="$(date +%s)"
  fi
fi
export SOURCE_DATE_EPOCH

GIT_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
BUILD_DATE_ISO="$(date -u -d "@$SOURCE_DATE_EPOCH" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")"

# 2. Deshabilitar compilación incremental de Cargo (introduce no-determinismo)
export CARGO_INCREMENTAL=0

# 3. Flags deterministas para Rust / LLVM
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
RUST_SYSROOT="$(rustc --print sysroot 2>/dev/null || true)"

FLAGS_ARRAY=(
  "-C" "strip=debuginfo"
  "-C" "codegen-units=1"
  "--remap-path-prefix=${ROOT_DIR}=/cercano"
  "--remap-path-prefix=${CARGO_HOME_DIR}=/cargo"
)
if [[ -n "$RUST_SYSROOT" ]]; then
  FLAGS_ARRAY+=("--remap-path-prefix=${RUST_SYSROOT}=/rustc")
fi

# Anexar flags existentes de RUSTFLAGS si las hubiera
if [[ -n "${RUSTFLAGS:-}" ]]; then
  # Leer flags existentes separadas por espacio
  read -r -a EXTRA_RUSTFLAGS <<< "${RUSTFLAGS}"
  FLAGS_ARRAY+=("${EXTRA_RUSTFLAGS[@]}")
fi

# Usar CARGO_ENCODED_RUSTFLAGS (separador ASCII 0x1F) para soportar de forma segura rutas con espacios
printf -v CARGO_ENCODED_RUSTFLAGS "%s\x1f" "${FLAGS_ARRAY[@]}"
export CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS%?}"

# Mantener RUSTFLAGS para trazabilidad y herramientas que no usan el formato codificado
RUSTFLAGS_STR="${FLAGS_ARRAY[*]}"
if [[ ! "$ROOT_DIR" =~ [[:space:]] ]]; then
  export RUSTFLAGS="$RUSTFLAGS_STR"
else
  # Si la ruta contiene espacios, no exportar RUSTFLAGS para evitar que Cargo falle al dividir por espacios
  unset RUSTFLAGS || true
fi

# 3.1 Inyección defensiva de CXXFLAGS para dependencias C++ heredadas (ej. webm-sys / mkvparser.cc)
if [[ -z "${CXXFLAGS:-}" ]]; then
  if [[ "${TARGET_TRIPLE:-}" =~ msvc ]]; then
    export CXXFLAGS="/FIcstdint"
  else
    export CXXFLAGS="-include cstdint"
  fi
fi

# 4. Inyección de clave pública de perfil si se suministró
if [[ -n "$PROFILE_PUBLIC_KEY" ]]; then
  export CERCANO_PROFILE_PUBLIC_KEY="$PROFILE_PUBLIC_KEY"
fi

echo "================================================================================"
echo "Cercano - Compilación de Binario Base Reproducible"
echo "================================================================================"
echo "Manifest:           $MANIFEST_PATH"
echo "Binario destino:    $BIN_NAME"
echo "Commit Git:         $GIT_COMMIT"
echo "SOURCE_DATE_EPOCH:  $SOURCE_DATE_EPOCH ($BUILD_DATE_ISO)"
echo "Target:             ${TARGET_TRIPLE:-host-default}"
echo "Directorio salida:  $OUT_DIR"
echo "Flags de build:     $RUSTFLAGS_STR"
echo "================================================================================"

mkdir -p "$OUT_DIR"

if [[ $DO_CLEAN -eq 1 ]]; then
  echo "INFO: Limpiando directorio de compilación..."
  cargo clean --manifest-path "$MANIFEST_PATH"
fi

# -----------------------------------------------------------------------------
# Función auxiliar: compilar binario
# -----------------------------------------------------------------------------
compile_binary() {
  local target_dir="$1"
  local extra_args=()

  if [[ -n "$TARGET_TRIPLE" ]]; then
    extra_args+=(--target "$TARGET_TRIPLE")
  fi

  if [[ -n "$PACKAGE_NAME" ]]; then
    extra_args+=(-p "$PACKAGE_NAME")
  fi

  if [[ -n "$BIN_NAME" ]]; then
    extra_args+=(--bin "$BIN_NAME")
  fi

  echo "INFO: Ejecutando cargo build --release en $target_dir..." >&2
  CARGO_TARGET_DIR="$target_dir" cargo build --release \
    --manifest-path "$MANIFEST_PATH" \
    "${extra_args[@]}"

  # Ubicar el binario generado
  local bin_subpath="release/$BIN_NAME"
  if [[ -n "$TARGET_TRIPLE" ]]; then
    bin_subpath="$TARGET_TRIPLE/release/$BIN_NAME"
  fi

  local found_bin=""
  if [[ -f "$target_dir/$bin_subpath" ]]; then
    found_bin="$target_dir/$bin_subpath"
  elif [[ -f "$target_dir/$bin_subpath.exe" ]]; then
    found_bin="$target_dir/$bin_subpath.exe"
  else
    # Búsqueda fallback dentro del target_dir
    found_bin="$(find "$target_dir" -maxdepth 3 -type f \( -name "$BIN_NAME" -o -name "$BIN_NAME.exe" \) ! -name "*.d" ! -name "*.rlib" | head -n 1)"
  fi

  if [[ -z "$found_bin" || ! -f "$found_bin" ]]; then
    echo "ERROR: No se encontró el binario compilado '$BIN_NAME' en $target_dir" >&2
    exit 1
  fi

  echo "$found_bin"
}

# -----------------------------------------------------------------------------
# Función auxiliar: cálculo de hash SHA-256 portable
# -----------------------------------------------------------------------------
calc_sha256() {
  local filepath="$1"
  if command -v sha256sum &>/dev/null; then
    sha256sum "$filepath" | awk '{print $1}'
  elif command -v shasum &>/dev/null; then
    shasum -a 256 "$filepath" | awk '{print $1}'
  else
    echo "ERROR: Se requiere sha256sum o shasum para calcular sumas SHA-256." >&2
    exit 1
  fi
}

# -----------------------------------------------------------------------------
# Verificación de Reproducibilidad (TC-F3-021)
# -----------------------------------------------------------------------------
if [[ $DO_VERIFY -eq 1 ]]; then
  echo ""
  echo "--- INICIANDO VERIFICACIÓN DE REPRODUCIBILIDAD (TC-F3-021) ---"
  TMP_DIR_1="$(mktemp -d /tmp/cercano-repro-1-XXXXXX)"
  TMP_DIR_2="$(mktemp -d /tmp/cercano-repro-2-XXXXXX)"

  trap 'rm -rf "$TMP_DIR_1" "$TMP_DIR_2"' EXIT

  echo "[Pasada 1/2] Compilando en $TMP_DIR_1..."
  BIN_PASS_1="$(compile_binary "$TMP_DIR_1")"
  HASH_PASS_1="$(calc_sha256 "$BIN_PASS_1")"
  echo "Hash Pasada 1: $HASH_PASS_1"

  echo "[Pasada 2/2] Compilando en directorio independiente $TMP_DIR_2..."
  BIN_PASS_2="$(compile_binary "$TMP_DIR_2")"
  HASH_PASS_2="$(calc_sha256 "$BIN_PASS_2")"
  echo "Hash Pasada 2: $HASH_PASS_2"

  if [[ "$HASH_PASS_1" != "$HASH_PASS_2" ]]; then
    echo "ERROR: Las compilaciones no son idénticas (Fallo TC-F3-021)." >&2
    echo "  Pasada 1: $HASH_PASS_1 ($BIN_PASS_1)" >&2
    echo "  Pasada 2: $HASH_PASS_2 ($BIN_PASS_2)" >&2
    exit 1
  fi

  echo "OK: Verificación de reproducibilidad exitosa (TC-F3-021)."
  echo "    Ambas compilaciones independientes produjeron el mismo hash SHA-256: $HASH_PASS_1"

  # Copiar el binario verificado al directorio de salida
  FINAL_BIN_NAME="$(basename "$BIN_PASS_1")"
  cp -f "$BIN_PASS_1" "$OUT_DIR/$FINAL_BIN_NAME"
  PRIMARY_BIN="$OUT_DIR/$FINAL_BIN_NAME"
else
  BUILD_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT_DIR/target}"
  COMPILED_BIN="$(compile_binary "$BUILD_TARGET_DIR")"
  FINAL_BIN_NAME="$(basename "$COMPILED_BIN")"
  cp -f "$COMPILED_BIN" "$OUT_DIR/$FINAL_BIN_NAME"
  PRIMARY_BIN="$OUT_DIR/$FINAL_BIN_NAME"
fi

# -----------------------------------------------------------------------------
# Generación de Hashes y Verificación de Sumas SHA-256
# -----------------------------------------------------------------------------
FINAL_HASH="$(calc_sha256 "$PRIMARY_BIN")"
echo "$FINAL_HASH  $FINAL_BIN_NAME" > "$OUT_DIR/$FINAL_BIN_NAME.sha256"
echo "$FINAL_HASH  $FINAL_BIN_NAME" > "$OUT_DIR/SHA256SUMS"

echo ""
echo "--- VERIFICACIÓN DE CHECKSUM SHA-256 ---"
(
  cd "$OUT_DIR"
  if command -v sha256sum &>/dev/null; then
    sha256sum -c SHA256SUMS
  else
    shasum -a 256 -c SHA256SUMS
  fi
)
echo "OK: Suma SHA-256 verificada correctamente: $FINAL_HASH"

# -----------------------------------------------------------------------------
# Metadatos del Build (build-info.json)
# -----------------------------------------------------------------------------
RUSTC_VER="$(rustc --version 2>/dev/null || echo "unknown")"
CARGO_VER="$(cargo --version 2>/dev/null || echo "unknown")"

cat << EOF > "$OUT_DIR/build-info.json"
{
  "binary_name": "$FINAL_BIN_NAME",
  "sha256": "$FINAL_HASH",
  "git_commit": "$GIT_COMMIT",
  "source_date_epoch": $SOURCE_DATE_EPOCH,
  "build_date_iso": "$BUILD_DATE_ISO",
  "rustc_version": "$RUSTC_VER",
  "cargo_version": "$CARGO_VER",
  "target": "${TARGET_TRIPLE:-host}",
  "rustflags": "$RUSTFLAGS_STR",
  "reproducible": true
}
EOF
echo "OK: Metadatos generados en $OUT_DIR/build-info.json"

# -----------------------------------------------------------------------------
# Generación de SBOM (SPDX 2.3 JSON)
# -----------------------------------------------------------------------------
if [[ $DO_SBOM -eq 1 ]]; then
  echo ""
  echo "--- GENERANDO SBOM (SPDX 2.3 JSON) ---"
  SBOM_FILE="$OUT_DIR/sbom.spdx.json"
  SBOM_BIN_FILE="$OUT_DIR/$FINAL_BIN_NAME.spdx.json"

  if command -v python3 &>/dev/null; then
    python3 - << 'PYEOF' "$MANIFEST_PATH" "$FINAL_BIN_NAME" "$FINAL_HASH" "$GIT_COMMIT" "$BUILD_DATE_ISO" "$SBOM_FILE"
import sys, json, subprocess

manifest_path = sys.argv[1]
bin_name = sys.argv[2]
bin_hash = sys.argv[3]
git_commit = sys.argv[4]
created_iso = sys.argv[5]
sbom_output = sys.argv[6]

try:
    meta_raw = subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--manifest-path", manifest_path],
        stderr=subprocess.DEVNULL
    )
    metadata = json.loads(meta_raw)
except Exception as e:
    metadata = {"packages": []}

packages_spdx = []
packages_spdx.append({
    "SPDXID": "SPDXRef-Package-Primary",
    "name": bin_name,
    "versionInfo": "base",
    "downloadLocation": "NOASSERTION",
    "filesAnalyzed": False,
    "licenseConcluded": "AGPL-3.0-only",
    "licenseDeclared": "AGPL-3.0-only",
    "supplier": "Organization: Cercano Contributors",
    "checksums": [
        {
            "algorithm": "SHA256",
            "checksumValue": bin_hash
        }
    ]
})

relationships = [
    {
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relatedSpdxElement": "SPDXRef-Package-Primary",
        "relationshipType": "DESCRIBES"
    }
]

idx = 1
for pkg in metadata.get("packages", []):
    pkg_id = f"SPDXRef-Package-Dep-{idx}"
    idx += 1
    license_str = pkg.get("license") or "NOASSERTION"
    packages_spdx.append({
        "SPDXID": pkg_id,
        "name": pkg.get("name", "unknown"),
        "versionInfo": pkg.get("version", "unknown"),
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": license_str,
        "licenseDeclared": license_str,
        "supplier": f"Person: {', '.join(pkg.get('authors', [])) or 'NOASSERTION'}"
    })
    relationships.append({
        "spdxElementId": "SPDXRef-Package-Primary",
        "relatedSpdxElement": pkg_id,
        "relationshipType": "DEPENDS_ON"
    })

spdx_doc = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": f"Cercano-Base-Binary-SBOM-{bin_name}",
    "documentNamespace": f"https://cercano.local/spdx/{bin_name}-{git_commit}",
    "creationInfo": {
        "created": created_iso,
        "creators": [
            "Tool: Cercano-Builder",
            "Organization: Cercano Contributors"
        ],
        "licenseListVersion": "3.20"
    },
    "packages": packages_spdx,
    "relationships": relationships
}

with open(sbom_output, "w", encoding="utf-8") as f:
    json.dump(spdx_doc, f, indent=2, sort_keys=True)
PYEOF
  else
    # Fallback básico sin python3
    cat << EOF > "$SBOM_FILE"
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "Cercano-Base-Binary-SBOM-$FINAL_BIN_NAME",
  "documentNamespace": "https://cercano.local/spdx/$FINAL_BIN_NAME-$GIT_COMMIT",
  "creationInfo": {
    "created": "$BUILD_DATE_ISO",
    "creators": [
      "Tool: Cercano-Builder",
      "Organization: Cercano Contributors"
    ],
    "licenseListVersion": "3.20"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-Primary",
      "name": "$FINAL_BIN_NAME",
      "versionInfo": "base",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "licenseConcluded": "AGPL-3.0-only",
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "$FINAL_HASH"
        }
      ]
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package-Primary",
      "relationshipType": "DESCRIBES"
    }
  ]
}
EOF
  fi

  cp -f "$SBOM_FILE" "$SBOM_BIN_FILE"
  echo "OK: SBOM generado exitosamente en $SBOM_FILE y $SBOM_BIN_FILE"
fi

echo ""
echo "================================================================================"
echo "Compilación reproducible finalizada con éxito."
echo "Artefactos publicados en: $OUT_DIR"
echo "  Binario:   $OUT_DIR/$FINAL_BIN_NAME"
echo "  SHA-256:   $OUT_DIR/SHA256SUMS ($FINAL_HASH)"
echo "  BuildInfo: $OUT_DIR/build-info.json"
if [[ $DO_SBOM -eq 1 ]]; then
  echo "  SBOM:      $OUT_DIR/sbom.spdx.json"
fi
echo "================================================================================"
