# Plan de trabajo — F3: Generador de instaladores personalizados

**Versión:** 0.2 · **Fecha:** 2026-11-05 · Depende de: F1 cerrado, veredicto de S4 (H4) y F2-08 (auditoría de la API).

**Objetivo (M2):** a partir de un perfil JSON se obtiene un instalador Windows firmado, preconfigurado con servidor, clave y política, auditado y revocable.

## 1. Requisitos funcionales

| Entrada del perfil | Descripción |
|---|---|
| Servidor | Hosts de rendezvous, relay y API; clave pública del servidor |
| Identidad visual | Nombre visible, icono (por defecto `branding/png/cercano-icon.ico`), textos de «acerca de» (siempre con atribución AGPL) |
| Política inicial | Acceso desatendido sí/no, política de contraseñas, aprobación de conexiones, permisos por defecto (archivos, portapapeles, audio, terminal), ocultar o no ajustes de red |
| Instalación | Modo (instalador, portable), ruta, inicio automático, acceso directo, silencioso |
| Identificación | Grupo/etiqueta del dispositivo y propietario predeterminado |
| Caducidad | Fecha de caducidad del perfil y límite de usos opcionales |

| Salida | Descripción |
|---|---|
| Artefacto | `.exe` y `.msi` (para GPO/Intune/RMM) en Windows; Linux (.deb/AppImage) y macOS (.dmg) en fases posteriores |
| Metadatos | Hash SHA-256, ID de instalador, perfil usado, SBOM, firma Authenticode |
| Evidencia | Eventos `build.*` encadenados en la auditoría |

## 2. Enfoque técnico (sujeto a S4)

**Estrategia A (recomendada si H4 se confirma): compilar una vez, configurar muchas.**
Se compila un binario base por versión. El generador añade/empaqueta un *perfil firmado* (Ed25519, clave del generador) que el cliente verifica al arrancar contra una clave pública incluida en el binario base. Resultado: generación en segundos.

**Estrategia B (fallback o para cambios de recursos como icono y nombre):** compilación completa por perfil en un runner de CI, con caché agresiva. Resultado: minutos.

**Firma de código:** integración enchufable (signtool, osslsigncode o HSM/servicio en la nube). Mientras no exista certificado (D4), se usa uno de pruebas y los artefactos se etiquetan «NO PARA PRODUCCIÓN».

**Revocación:** cada instalador lleva un `installer_id`; `cercano-api` mantiene lista de revocación y el servidor rechaza registros y conexiones de instaladores revocados o caducados.

## 3. Reglas de seguridad del generador

- El instalador nunca oculta su presencia: icono/indicador visible y entrada en «Programas y características».
- Los perfiles no incluyen credenciales de administrador; solo claves públicas y tokens de registro de menor privilegio, con caducidad.
- Las claves de firma del generador y de Authenticode no salen del servicio de firma y no se guardan en el repositorio ni en artefactos.
- Cada generación exige un usuario autenticado con permiso `builder:create` y queda auditada (quién, perfil, resultado, hash).
- Los instaladores generados se pueden rastrear hasta el perfil y el usuario que los creó.

## 4. Tareas

| ID | Tarea | Dep. | Rol | Verifica |
|---|---|---|---|---|
| F3-01 | Esquema y versionado del perfil | F0-07 | Builder | Seguridad |
| F3-02 | Cliente: lectura y verificación de perfil firmado | F3-01 | Cliente | Seguridad |
| F3-03 | Binario base reproducible y publicación de artefactos base | F0-05, F0-03 | Builder | QA |
| F3-04 | CLI `cercano-build` | F3-01, F3-02, F3-03 | Builder | QA |
| F3-05 | Empaquetado Windows (.exe y .msi) | F3-04 | Builder | QA |
| F3-06 | Firma Authenticode enchufable | F3-05 | Builder | Seguridad |
| F3-07 | Servicio de build en `cercano-api`: cola, jobs, almacenamiento | F3-04, F1-04 | ControlPlane | QA |
| F3-08 | Auditoría `build.*` | F3-07, F2-02 | ControlPlane | QA |
| F3-09 | Revocación y caducidad | F3-02, F3-07 | ControlPlane + Servidor | Seguridad |
| F3-10 | SBOM y verificación de procedencia | F3-04 | Builder | Seguridad |
| F3-11 | Guía de despliegue masivo | F3-05 | Coordinador | QA |
| F3-12 | Pruebas de extremo a extremo y cierre | F3-01…11 | QA | Coordinador |

### Detalle

**F3-01 Esquema del perfil.**
JSON Schema `docs/specs/cercano-profile.schema.json` con versión, campos de la sección 1, valores por defecto y reglas de validación (hosts válidos, longitudes, caracteres permitidos). Política de compatibilidad hacia atrás entre versiones del perfil.
*CA:* ejemplos válidos e inválidos cubiertos por pruebas; perfiles con campos desconocidos se rechazan o ignoran según política documentada.

**F3-02 Cliente: perfil firmado.**
Parche mínimo: al arrancar, localizar el perfil embebido, verificar firma y caducidad, aplicar la configuración y rechazar perfiles manipulados. La clave pública de verificación es configurable en tiempo de compilación.
*CA:* perfil alterado en un solo byte → rechazado y evento registrado; perfil caducado → rechazado; perfil válido → configuración aplicada (TC-F3-001…008).

**F3-03 Binario base reproducible.**
Pipeline de CI que produce el binario base por versión y plataforma, con caché de dependencias, SBOM y hashes publicados. Documentar cómo reproducir el build localmente.
*CA:* dos builds del mismo commit producen el mismo hash (o la diferencia queda explicada y acotada).

**F3-04 CLI `cercano-build`.**
`cercano-build --profile perfil.json --out dist/` produce artefacto y metadatos; modo `--dry-run` valida el perfil; salida determinista para el mismo perfil y base.
*CA:* genera en < 30 s con la estrategia A (objetivo propuesto); errores claros ante perfiles inválidos.

**F3-05 Empaquetado Windows.**
`.exe` (instalador) y `.msi` con instalación silenciosa y parámetros documentados; actualización sobre una instalación previa; desinstalación limpia.
*CA:* instalación, actualización y desinstalación en Windows 10 y 11 limpios sin restos (verificado por QA en el laboratorio); `.msi` desplegable por línea de comandos.

**F3-06 Firma enchufable.**
Interfaz de firmante con implementaciones para signtool/osslsigncode; la clave solo vive en el servicio de firma. Sello de tiempo obligatorio.
*CA:* la firma se verifica con `Get-AuthenticodeSignature`; si falla la firma, el job falla y no se publica el artefacto.

**F3-07 Servicio de build.**
Endpoints `POST /builds`, `GET /builds/{id}`, descarga firmada con caducidad; cola con límite de concurrencia; almacenamiento de artefactos con retención configurable; permisos `builder:create` y `builder:download`.
*CA:* flujo completo por API; un usuario sin permiso recibe 403 y queda un evento `auth.denied`.

**F3-08 Auditoría `build.*`.**
Eventos `build.requested`, `build.started`, `build.completed`, `build.failed`, `build.downloaded`, `build.revoked`, con ID de instalador, hash, perfil (sin secretos) y actor.
*CA:* cada ejecución deja la secuencia completa y verificable.

**F3-09 Revocación y caducidad.**
`cercano-api` publica la lista de revocados; hbbs la consulta (con caché y degradación segura configurable) y rechaza registros/conexiones de instaladores revocados o caducados; evento por cada rechazo.
*CA:* tras revocar, el instalador deja de poder registrarse en menos de 60 s (objetivo propuesto); rechazo auditado.

**F3-10 SBOM y procedencia.**
SBOM (CycloneDX o SPDX) por artefacto, hashes y atestación de procedencia del build en CI.
*CA:* cada artefacto publicado trae SBOM y hash verificables.

**F3-11 Guía de despliegue masivo.**
Guía para GPO, Intune y herramientas RMM: parámetros silenciosos, verificación posterior, desinstalación, actualización y manejo de antivirus/SmartScreen.
*CA:* un agente que no la escribió la sigue de cero y logra el despliegue en el laboratorio.

**F3-12 Pruebas E2E y cierre.**
Casos TC-F3-*: perfil → instalador → instalación → registro → conexión → auditoría → revocación; manipulación de perfiles; instaladores caducados; fallo de firma; reproducibilidad.
*CA:* suite verde; informe `docs/status/F3-cierre.md`.

**Gate F3 (M2):** flujo completo demostrado en el laboratorio; ninguna clave privada presente en artefactos ni repositorio (verificación automática); revisión de seguridad sin hallazgos altos; SBOM y firmas verificables.

## 5. Fuera de alcance en F3

Generación para Linux y macOS (se planifica al cierre de F3), interfaz web del generador (F4) y notarización de macOS.
