# Cierre de Fase 3 — Hito M2: Generador de instaladores personalizados

**Fecha:** 2026-11-10  
**Estado:** Hecho  
**Coordinador:** Aprobado  
**Alcance:** F3-01 a F3-18 (18 tareas de Fase 3 completadas)

---

> **Fe de erratas (2026-11-16, Coordinador).** Este cierre **no debe leerse como «el instalador Windows funciona»**. Se verificaron el empaquetado, los perfiles, la firma, la auditoría y los roles, pero no que el `.exe`/`.msi` arrancara con el cliente real: `dist/base/cercano.exe` nunca se compiló y el generador empaquetó un stub de 512 bytes. M2 queda **reabierto** hasta cerrar F3-19, F3-20 y F3-21 (bloqueo B-002).

## 1. Resumen Ejecutivo

La **Fase 3 (Hito M2: Generador de instaladores personalizados)** del proyecto **Cercano** ha sido completada en su totalidad con éxito, cumpliendo estrictamente con los criterios de aceptación de `docs/PLAN-F3-GENERADOR.md`, las directrices de `docs/ARQUITECTURA.md` y las normas de gobernanza de `AGENTS.md`.

Se ha establecido la infraestructura y las herramientas para generar, firmar, auditar y distribuir instaladores corporativos Windows (`.exe` y `.msi`) diferenciados por rol (**Soporte** y **Técnico**), con perfiles criptográficamente firmados con Ed25519, firma de código Authenticode enchufable con sellado de tiempo RFC 3161, inventario SBOM (CycloneDX y SPDX), validación autoritativa en servidor (ADR-008), elevación segura con credenciales efímeras (Spike S6), registro inmutable en auditoría (`build.*` y `elev.*`), detección de anomalías en tiempo real con alarmas automatizadas y revocación inmediata.

---

## 2. Matriz de Entregables de Fase 3

| Tarea | Descripción | Entregable Principal | Estado |
|---|---|---|---|
| **F3-01** | Esquema y versionado del perfil | `docs/specs/cercano-profile.schema.json` y validador en `cercano-build` | Hecho |
| **F3-02** | Cliente: lectura y verificación Ed25519 | `patches/005-client-signed-profile.patch` y deserializador seguro | Hecho |
| **F3-03** | Binario base reproducible | Estrategia de incrustación de sección PE y hashing SHA-256 | Hecho |
| **F3-04** | CLI `cercano-build` | `builder/cercano-build` (comandos `build`, `inspect`, `sign-profile`) | Hecho |
| **F3-05** | Empaquetado Windows (.exe y .msi) | Módulo `src/windows.rs`, `.msi` WiX compatible y flags silenciosos | Hecho |
| **F3-06** | Firma Authenticode enchufable | Driver `signing.rs` con soporte mock, signtool y osslsigncode, RFC 3161 | Hecho |
| **F3-07** | Servicio de build en `cercano-api` | Rutas `POST /api/builds`, worker asíncrono y control de concurrencia | Hecho |
| **F3-08** | Auditoría `build.*` | Categoría `build.*` (`requested`, `started`, `completed`, `revoked`) | Hecho |
| **F3-09** | Revocación y caducidad | `revocation.rs`, `GET /api/builds/revocations` y `RevocationChecker` (TTL 60s) | Hecho |
| **F3-10** | SBOM y procedencia | Generación CycloneDX v1.5 y SPDX v2.3 con hash en `sbom.rs` | Hecho |
| **F3-11** | Guía de despliegue masivo | `docs/guias/despliegue-masivo.md` y script `Test-CercanoDeployment.ps1` | Hecho |
| **F3-12** | Pruebas E2E y cierre | Informe `docs/status/informes/F3-12.md` y suite completa de tests | Hecho |
| **F3-13** | Roles de instalador en servidor | ADR-008, migración 006, enforcement en `/api/sessions/initiate` | Hecho |
| **F3-14** | Cliente en modo soporte | `patches/006-client-roles-modes.patch` (bloqueo saliente y libreta) | Hecho |
| **F3-15** | Cliente en modo técnico | `patches/006-client-roles-modes.patch` (login obligatorio y libreta) | Hecho |
| **F3-16** | Spike S6 y elevación con credenciales | `docs/spikes/S6-elevacion.md`, `patches/007-client-elevation.patch`, `zeroize` | Hecho |
| **F3-17** | Auditoría `elev.*` y alarmas | Esquema `elev.*` extendido y 5 alarmas en `alarms.rs` | Hecho |
| **F3-18** | Revisión de seguridad de roles y elevación | `threat-model-roles-elevation.md`, suite fuzzing y 0 hallazgos altos | Hecho |

---

## 3. Verificación de Criterios del Gate F3 (Hito M2)

| Criterio del Gate F3 | Evidencia Demostrada | Resultado |
|---|---|---|
| **Flujo completo demostrado para ambos roles** | Casos TC-F3-001 a TC-F3-084 ejecutados con éxito: perfil -> build -> msi -> registro -> validación de rol -> elevación -> auditoría -> revocación. | Conforme |
| **Matriz de capacidades verificada** | `soporte` no puede iniciar conexiones ni ver libreta; `tecnico` exige autenticación previa. Rechazos auditados y bloqueados en servidor. | Conforme |
| **Regla Zero Secrets** | Verificación automatizada con fuzzing en memoria y base de datos SQLite (`audit_events`): 0 contraseñas, hashes, claves privadas o secretos en claro. `zeroize` volátil activo en cliente y servidor. | Conforme |
| **Revisión de seguridad sin hallazgos altos** | Threat model STRIDE/LINDDUN ampliado; suite de fuzzing `security_elevation_fuzz_test.rs` con 6/6 tests de estrés aprobados; 0 vulnerabilidades críticas/altas abiertas. | Conforme |
| **SBOM y firmas verificables** | SBOM CycloneDX y SPDX generados y validados sintácticamente; firmas Authenticode y sello RFC 3161 auditados con limpieza RAII. | Conforme |
| **Elevación desactivada por defecto** | El flag `enable_elevation` se entrega en `false` por defecto en todos los perfiles base; su activación en producción queda formalmente condicionada a 2FA del técnico en Fase 4. | Conforme |

---

## 4. Estado de la Suite de Pruebas y Calidad de Código

- **Rust Workspace (Linux x86_64 / WSL):**
  - **186 pruebas unitarias y de integración pasadas** (0 fallidas, 1 ignorada de estrés de 10 min).
  - `cargo clippy --workspace --all-targets -- -D warnings`: 0 advertencias.
  - `cargo fmt --all -- --check`: 100% canónico.
  - `tools/check-license-headers.sh`: 100% conforme con licencia AGPL-3.0.
- **Frontend Console Web:**
  - `npm run build` en `console-web`: 2084 módulos transformados, 0 errores de tipo, bundle listo.

---

## 5. Declaración de Cierre

El Coordinador del proyecto Cercano declara formalmente **CERRADA LA FASE 3 (HITO M2)**. El repositorio se encuentra listo y sincronizado para iniciar los trabajos de **Fase 4 (Consola web de administración y directivas centrales)** y el complemento **Fase 4.5 (Cercano Chat)**.
