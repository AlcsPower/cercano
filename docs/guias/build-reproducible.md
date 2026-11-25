# Guía Técnica: Compilación Reproducible del Binario Base y Publicación de Artefactos

**Código:** GUIA-BUILD-001  
**Componentes:** `builder/build-base.sh`, `.github/workflows/base-binary.yml`  
**Criterios de Aceptación Asociados:** TC-F3-021, F3-03, F3-10  
**Licencia:** AGPL-3.0-only  

---

## 1. Fundamentos y Objetivos de Reproducibilidad

En Cercano, la **reproducibilidad del binario base** es una garantía de seguridad crítica para la cadena de suministro de software (*Supply Chain Security*). Un proceso de compilación es determinista y reproducible cuando, partiendo del mismo código fuente (mismo commit de Git) y del mismo entorno de compilación, produce un binario ejecutable idéntico byte a byte, con la misma suma criptográfica SHA-256.

### Objetivos estratégicos:
1. **Auditoría independiente sin confianza ciega:** Cualquier auditor o cliente puede compilar el código fuente en su propia infraestructura y comprobar que el binario resultante coincide exactamente con los artefactos oficiales distribuidos en las publicaciones de Cercano.
2. **Defensa contra ataques a la cadena de suministro:** Protege contra troyanos o manipulaciones introducidas por servidores de compilación o corredores de CI/CD comprometidos.
3. **Pilar de la Arquitectura de Fase 3 (ADR-005):** El generador de instaladores (`cercano-build`) opera bajo el principio *«compilar una vez, configurar muchas»*. Se compila un único binario base reproducible por versión; posteriormente, los instaladores especializados por rol (`soporte` o `tecnico`) se producen en cuestión de segundos inyectando el perfil firmado con Ed25519 sin necesidad de recompilación.

---

## 2. Factores de No-Determinismo y Mitigaciones

Los compiladores modernos introducen múltiples fuentes de variabilidad accidental. Cercano mitiga cada una de ellas de forma sistemática a través de variables de entorno y flags de compilación:

| Fuente de No-Determinismo | Causa Técnica | Mitigación Implementada |
|---|---|---|
| **Rutas locales del sistema** | El compilador incrusta rutas absolutas (`/home/usuario/...` o `C:\Users\...`) en cadenas de pánico y símbolos debug. | Flags `--remap-path-prefix=<RUTA_PROYECTO>=/cercano` y `--remap-path-prefix=$CARGO_HOME=/cargo`. |
| **Timestamps del reloj** | Macros como `file!()`, metadatos PE/ELF o fechas de creación de archivos cambian en cada segundo. | Variable de entorno estándar `SOURCE_DATE_EPOCH` fijada al timestamp Unix del commit de Git (`git log -1 --pretty=%ct`). |
| **Caché incremental de Cargo** | La compilación incremental reutiliza unidades parciales generando ordenamientos arbitrarios. | Variable `CARGO_INCREMENTAL=0` obligatoria. |
| **Paralelismo de código LLVM** | Múltiples hilos de codegen particionan módulos de manera no determinista. | Flag de Rust `-C codegen-units=1`. |
| **Tablas de depuración no idénticas** | DWARF y PDB pueden contener identificadores de compilación aleatorios. | Flag `-C strip=debuginfo` en el binario base distribuido. |
| **Rutas con espacios en el host** | En Windows/OneDrive o Linux con rutas con espacios, `RUSTFLAGS` se fragmenta por espacios en blanco. | Uso de `CARGO_ENCODED_RUSTFLAGS` con el delimitador ASCII estándar `0x1F` (Unit Separator). |

---

## 3. Entorno Hermético y Cerrado

Para garantizar que dos compilaciones sucesivas produzcan el mismo hash en diferentes máquinas:

1. **Toolchain de Rust fijado:**
   - Se debe utilizar la misma versión del compilador `rustc` y `cargo` (especificada en el entorno o vía `rust-toolchain.toml`).
2. **Dependencias congeladas:**
   - El archivo `Cargo.lock` debe estar versionado y no modificarse. Las compilaciones en CI utilizan `--locked`.
3. **Aislamiento de variables de entorno:**
   - El script `builder/build-base.sh` unifica y normaliza las variables relevantes (`SOURCE_DATE_EPOCH`, `CARGO_INCREMENTAL`, `RUSTFLAGS`, `CXXFLAGS`).
   - `CXXFLAGS` siempre lleva `-include cstdint` (antepuesto a lo que ya tuviera el entorno): `libwebm`, compilada por la dependencia git `webm-sys` de `vendor/client`, usa `uint32_t`/`uint64_t` sin incluir `<cstdint>` y no compila con GCC ≥ 13. Es un flag constante, no introduce no-determinismo, y queda registrado en `build-info.json` (`cxxflags`). Se aplica en el script, no en el workflow, para que una compilación local reproduzca el mismo binario que CI.

---

## 4. Uso del Script `builder/build-base.sh`

El script `builder/build-base.sh` es la herramienta estándar para generar binarios reproducibles tanto en entornos locales como en flujos de integración continua.

### 4.1. Sintaxis y Parámetros

```bash
builder/build-base.sh [OPCIONES]
```

| Opción | Descripción | Valor por defecto |
|---|---|---|
| `--manifest-path <RUTA>` | Ruta al `Cargo.toml` a compilar | `vendor/client/Cargo.toml` |
| `--bin <NOMBRE>` | Nombre del binario a compilar | `cercano` |
| `--package <NOMBRE>` | Nombre del paquete Cargo | Auto-detectado |
| `--target <TRIPLE>` | Target de arquitectura (ej. `x86_64-unknown-linux-gnu`) | Target nativo del host |
| `--out-dir <DIRECTORIO>` | Carpeta de salida para artefactos, hashes y SBOM | `dist/base` |
| `--profile-public-key <KEY>` | Clave pública Ed25519 Base64 incrustada en el binario | Clave de desarrollo |
| `--verify` | Ejecuta dos compilaciones completas en targets aislados y verifica que sus hashes SHA-256 sean idénticos (**TC-F3-021**) | Desactivado |
| `--sbom` | Genera el Software Bill of Materials en formato SPDX 2.3 JSON | Desactivado |
| `--clean` | Limpia artefactos previos antes de iniciar | Desactivado |
| `-h, --help` | Muestra la ayuda y opciones | - |

### 4.2. Ejemplos de Ejecución

#### Compilación básica local
```bash
bash builder/build-base.sh
```

#### Compilación completa con verificación de reproducibilidad y SBOM
```bash
bash builder/build-base.sh --verify --sbom --out-dir dist/base
```

#### Compilación con clave pública de verificación de perfil personalizada
```bash
bash builder/build-base.sh \
  --profile-public-key "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=" \
  --verify \
  --sbom
```

---

## 5. Artefactos Generados y Verificación de Sumas SHA-256

Al finalizar la compilación, el directorio de salida (por defecto `dist/base/`) contiene los siguientes artefactos:

```
dist/base/
├── cercano                 # Binario ejecutable base reproducible
├── cercano.sha256          # Hash SHA-256 del binario individual
├── SHA256SUMS              # Suma criptográfica en formato estándar sha256sum
├── build-info.json         # Metadatos del entorno y commit
└── sbom.spdx.json          # Software Bill of Materials (SPDX 2.3 JSON)
```

### 5.1. Verificación de la suma SHA-256
Para verificar la integridad del binario compilado:

```bash
cd dist/base
sha256sum -c SHA256SUMS
```

Salida esperada:
```text
cercano: OK
```

### 5.2. Metadatos del Build (`build-info.json`)
El archivo `build-info.json` registra la procedencia exacta de la compilación para auditoría:

```json
{
  "binary_name": "cercano",
  "sha256": "4b92b6a9e1e98e27efad044c3ec3e5f2a1...",
  "git_commit": "9cbd3707b76775630487c5e8e7fec3297d931801",
  "source_date_epoch": 1794242123,
  "build_date_iso": "2026-11-09T16:35:23Z",
  "rustc_version": "rustc 1.99.1 (5f94df478 2026-08-27)",
  "cargo_version": "cargo 1.99.1 (5f94df478 2026-08-27)",
  "target": "host",
  "rustflags": "-C strip=debuginfo -C codegen-units=1 --remap-path-prefix=...",
  "reproducible": true
}
```

---

## 6. Generación y Validación del SBOM (SPDX 2.3)

El Software Bill of Materials (SBOM) describe de manera exhaustiva todos los componentes, dependencias directas e indirectas, autores y licencias que componen el binario base.

### 6.1. Formato SPDX 2.3 JSON
El archivo `sbom.spdx.json` cumple con el estándar internacional ISO/IEC 5962:2021 (SPDX 2.3):
- **Documento:** Declarado bajo licencia `CC0-1.0`.
- **Paquete Principal:** El binario base (`cercano`), con su hash SHA-256 y licencia `AGPL-3.0-only`.
- **Dependencias:** Cada crate listado a partir de `cargo metadata`, con su identificador `SPDXID`, versión, licencia declarada y relación `DEPENDS_ON`.

### 6.2. Validación Sintáctica del SBOM
Se puede validar la estructura JSON del SBOM localmente con Python o `jq`:

```bash
python3 -m json.tool dist/base/sbom.spdx.json > /dev/null && echo "SBOM válido"
```

O inspeccionar las licencias de dependencias incluidas:
```bash
jq '.packages[] | {name: .name, version: .versionInfo, license: .licenseConcluded}' dist/base/sbom.spdx.json
```

---

## 7. Procedimiento de Verificación de Reproducibilidad (TC-F3-021)

El caso de prueba **TC-F3-021** establece:
> *«Dos compilaciones sucesivas del mismo commit producen el mismo hash SHA-256 (o la diferencia queda explicada y acotada)»*.

### 7.1. Verificación Automatizada con el Script
La forma más directa es utilizar la bandera `--verify`:

```bash
bash builder/build-base.sh --verify
```

El script realiza de manera autónoma:
1. Crea un directorio temporal aislado `/tmp/cercano-repro-1-XXXXXX`.
2. Compila el binario en Release y calcula el hash $H_1$.
3. Crea un segundo directorio temporal aislado `/tmp/cercano-repro-2-XXXXXX`.
4. Compila nuevamente el binario en Release y calcula el hash $H_2$.
5. Compara $H_1$ y $H_2$:
   - Si $H_1 == H_2$, confirma la reproducibilidad bit-a-bit con código de salida `0`.
   - Si $H_1 \ne H_2$, reporta el error y detiene el proceso con código `1`.

### 7.2. Verificación Manual Paso a Paso
Para ejecutar la comprobación de forma manual e independiente:

```bash
# 1. Fijar SOURCE_DATE_EPOCH del commit
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
export CARGO_INCREMENTAL=0

# 2. Compilación en Carpeta A
CARGO_TARGET_DIR=/tmp/build-a cargo build --release
HASH_A=$(sha256sum /tmp/build-a/release/cercano | awk '{print $1}')

# 3. Compilación en Carpeta B
CARGO_TARGET_DIR=/tmp/build-b cargo build --release
HASH_B=$(sha256sum /tmp/build-b/release/cercano | awk '{print $1}')

# 4. Comparación
echo "Hash A: $HASH_A"
echo "Hash B: $HASH_B"
test "$HASH_A" = "$HASH_B" && echo "TC-F3-021: PASÓ (Hashes idénticos)"
```

### 7.3. Depuración ante Divergencias
Si dos compilaciones generaran hashes distintos, se debe utilizar `diffoscope` para inspeccionar la diferencia en las secciones binarias:

```bash
diffoscope /tmp/build-a/release/cercano /tmp/build-b/release/cercano
```
Las causas típicas suelen ser:
- Omisión de `CARGO_INCREMENTAL=0`.
- Una ruta del host no cubierta por `--remap-path-prefix`.
- Uso de macros dependientes del tiempo (`chrono::Utc::now()`, `std::time::SystemTime` invocados en build scripts `build.rs`).

---

## 8. Integración Continua (CI)

El workflow de GitHub Actions está configurado en `.github/workflows/base-binary.yml`:
1. **Desencadenadores:** Ejecución en cada `push` a ramas principales (`main`, `feat/**`), tags de versión (`v*`) y ejecuciones manuales (`workflow_dispatch`).
2. **Pasos:**
   - Comprobación de licencias AGPL-3.0 (`tools/check-license-headers.sh`).
   - Aplicación de parches ordenados (`tools/apply-patches`).
   - Compilación con verificación doble (`--verify`) y generación de SBOM (`--sbom`).
   - Verificación de sumas SHA-256 (`sha256sum -c SHA256SUMS`).
   - Validación estructural del SBOM SPDX.
   - Publicación de artefactos con retención de 14 días.
