# Plan de trabajo — F7: Endurecimiento y release beta

**Versión:** 0.2 · **Fecha:** 2026-11-10 · **Estado:** revisado por el Coordinador el 2026-11-10; pendiente de aprobación del dueño · **Duración estimada:** 3 semanas  
**Objetivo (M4):** preparar una beta pública verificable y operable, con revisión de seguridad, cadena de suministro, artefactos firmados, procedimientos de actualización/recuperación y criterios claros de soporte.  
**Depende de:** cierre de F6; gates de F0–F5; conexión directa/relay, auditoría, generador, consola y documentación de las capacidades que se anuncien. Las funciones diferidas no se presentan como disponibles.  
**Referencias:** `docs/ROADMAP.md`, `docs/ARQUITECTURA.md`, `docs/PLAN-DE-PRUEBAS.md`, `AGENTS.md`, `SECURITY.md`, `NOTICE`, `deploy/` y los informes de cierre previos.

## 1. Alcance y definición de beta

F7 no añade paridad funcional grande: estabiliza, verifica, documenta y empaqueta lo entregado. El Coordinador y el dueño fijan la matriz de plataformas/funciones que se publican y los riesgos aceptados antes de construir el candidato. El cliente web integrado sigue fuera de alcance v1.

La beta debe permitir instalación limpia, actualización desde una versión Cercano soportada, respaldo/restauración probados, verificación offline de auditoría y reversión segura. No se promete compatibilidad con instalaciones upstream salvo pruebas y documentación explícitas. Ningún certificado, clave privada o secreto de firma se almacena en Git ni en el artefacto.

## 2. Tareas

| ID | Tarea | Dep. | Rol | Verifica |
|---|---|---|---|---|
| F7-01 | Definir alcance beta, matriz de plataformas/funciones, soporte y criterios de aceptación; actualizar roadmap y pruebas | F6 | Coordinador + Dueño | QA |
| F7-02 | Revisión integral de amenazas STRIDE/LINDDUN y controles, incluyendo identidad, elevación, chat, LAN y operaciones | F7-01 | Seguridad | Coordinador |
| F7-03 | Pentest interno autorizado en laboratorio, análisis de abuso y pruebas de autorización/IDOR | F7-02 | Seguridad + QA | Coordinador |
| F7-04 | Corregir hallazgos y verificar mitigaciones; reevaluar riesgos residuales | F7-03 | Roles responsables | Seguridad independiente |
| F7-05 | Revisión de dependencias, licencias, CVE, SBOM y procedencia por artefacto | F7-01 | Builder + Seguridad | QA |
| F7-06 | Build reproducible, firma de release, verificación de firmas y proceso de publicación | F7-05 | Builder | Seguridad/QA |
| F7-07 | Gestión de secretos/llaves operativas: generación, almacenamiento, rotación, backup y recuperación documentados | F7-02 | ControlPlane + Servidor | Seguridad |
| F7-08 | Prueba de respaldo/restauración y continuidad (API, BD, checkpoints, configuración y artefactos según retención) | F7-07 | ControlPlane + QA | Seguridad |
| F7-09 | Compatibilidad y actualización: instalación limpia, upgrade, migraciones y rollback documentado | F7-01, F7-06 | Builder + QA | Coordinador |
| F7-10 | Revisión de privacidad, minimización de datos, retención y guías de operador/usuario | F7-02 | Seguridad + Coordinador | Dueño |
| F7-11 | Observabilidad y operación: health checks, alertas, capacidad, respuesta a incidentes y recuperación | F7-08/09 | ControlPlane + Servidor | QA |
| F7-12 | Candidato beta (RC), pruebas de aceptación y publicación de notas/artefactos | F7-04…11 | Builder + QA | Dueño/Coordinador |
| F7-13 | Informe de cierre, inventario de deuda y gate M4 | F7-12 | Coordinador | Dueño |

## 3. Criterios de aceptación

- **F7-01:** matriz de alcance nombra versiones/plataformas, funciones entregadas, funciones no soportadas, el estado en la beta de cada función sensible (elevación con credenciales, LAPS, Cercano Chat, OIDC/LDAP, descubrimiento LAN, WebSocket: activada, desactivada por defecto o no incluida), proceso de reporte de errores, datos recopilados y canales de actualización. Cada promesa tiene evidencia en CI o laboratorio.
- **F7-02/03:** revisión de amenazas actualizada contra arquitectura implementada y no solo la prevista; pruebas autorizadas exclusivamente sobre el laboratorio Cercano. Se cubren autenticación/2FA, RBAC, IDOR, perfiles y roles de instalador, revocación, LAPS si fue aprobado, chat/adjuntos, hash chain, relays, API expuesta y despliegue. Hallazgos tienen severidad, evidencia protegida, responsable y fecha objetivo.
- **F7-04:** cero hallazgos críticos/altos abiertos. Hallazgos medios/bajos tienen mitigación, responsable, vencimiento y aceptación explícita del dueño para la beta; un cambio de código se vuelve a probar por un agente distinto.
- **F7-05:** inventario de dependencias directas/transitivas, licencias AGPL compatibles, avisos de atribución, SBOM CycloneDX o SPDX y escaneo de vulnerabilidades por cada artefacto publicado. CVE aceptadas o no corregibles quedan justificadas; no se ignoran silenciosamente.
- **F7-06:** build desde tag/commit inmutable en runner controlado; hashes/atestación asociados; firma verificable de los artefactos disponibles en la beta; verificación de firma falla de forma cerrada ante alteración. Claves de firma segregadas y no accesibles al job de build ordinario.
- **F7-07/08:** procedimiento paso a paso para claves, rotación, respaldo cifrado y restauración; prueba de que los checkpoints siguen verificables tras restauración; nunca se respalda material sin cifrar de forma accidental; objetivo de recuperación y pérdida de datos acordado y medido. El procedimiento manual cubre la base de datos (`cercano.db`), las claves, los adjuntos del chat, los checkpoints y la configuración: la guía de respaldo actual del chat no incluye `cercano.db` y se corrige aquí. F8 lo automatizará después.
- **F7-09:** instalación limpia y upgrade soportado desde versiones declaradas, migraciones en BD representativa, backup antes de actualizar y procedimiento de recuperación. No se afirma rollback automático de migraciones destructivas; se documenta su límite.
- **F7-10/11:** guía de migración desde una instalación RustDesk OSS (hito M4 del roadmap) o decisión de F7-01 de sacarla de la beta y actualizar el roadmap; guías sobre TLS, puertos, usuarios de servicio, firewall, retención, desactivación de funciones, incidentes, actualizaciones y monitoreo; logs no contienen contraseñas, tokens, secretos TOTP/LAPS, mensajes de chat ni credenciales de firma.
- **F7-12/13:** RC probado en CI y laboratorio, notas de versión con hashes/SBOM/licencias/conocidos, evidencia firmada por QA/Seguridad y aprobación del dueño. Publicación solo después del gate completo; informe `docs/status/F7-cierre.md`.

## 4. Pruebas y evidencia

Crear `tests/cases/TC-F7-*.md` y registrar en `docs/PLAN-DE-PRUEBAS.md` durante F7-01. La batería incluirá:

| Grupo | Evidencia requerida |
|---|---|
| Seguridad | Pentest interno en laboratorio, autorización, alcance, hallazgos redactados y retest independiente |
| Cadena de suministro | SBOM, `cargo audit`, `cargo deny check`, SAST, búsqueda de secretos y verificación de licencias/NOTICE |
| Reproducibilidad | Build repetido del mismo tag; comparación de hashes y explicación acotada de diferencias no deterministas |
| Firma | Artefacto íntegro acepta firma; artefacto alterado o firma/certificado inválido se rechaza |
| Integridad | `cercano-audit verify` sobre exportación y sobre datos restaurados con checkpoints |
| Upgrade/restore | Instalación, actualización, migración, restauración y recuperación ante interrupción del proceso |
| Compatibilidad | Matriz de plataformas declaradas, instalación/desinstalación y conexión directa/relay |
| Operación | Health checks, alertas, rotación, revocación, retención y guía de incidentes ejecutados por otra persona |
| Privacidad | Búsqueda automatizada de secretos y muestreo de logs/auditoría/exportaciones/notificaciones |

**Gate F7 / M4:** todas las tareas cerradas o diferidas con aceptación documentada; la elevación con credenciales solo se habilita en producción con 2FA obligatoria para técnicos y F3-18 cerrada; pruebas de fase en verde; cero críticos/altos; riesgos restantes aceptados por el dueño; firmas, hashes, SBOM, NOTICE y código fuente correspondientes disponibles; restore y actualización demostrados; documentación y proceso de reporte publicados; RC aprobado. Un pentest sin retest o un backup no restaurado no satisface el gate.

## 5. Riesgos y límites

| Riesgo | Mitigación |
|---|---|
| Beta se interpreta como garantía de disponibilidad | Etiquetado claro, alcance limitado, soporte y limitaciones publicados |
| Firma/build comprometidos | Separar firma de build, proteger claves, atestación y verificación independiente |
| Vulnerabilidad crítica pendiente | Bloquear publicación; divulgación coordinada y plan privado conforme a `SECURITY.md` |
| Restauración pierde integridad | Simulacro con backups reales sintéticos y verificación de checkpoints |
| Upgrade causa pérdida de datos | Backup previo, migraciones ensayadas, procedimiento de recuperación y compatibilidad declarada |
| Dependencia o licencia incompatible | Escaneo por artefacto, revisión humana y resolución antes de distribuir |
| Exceso de alcance en hardening | No introducir funciones nuevas; aplazar extras fuera de matriz beta |

## 6. Fuera de alcance

SLA de producción, certificaciones regulatorias formales, pentest de terceros contratado (se planifica por separado), soporte a plataformas no incluidas en la matriz, automatización de actualización forzada, cliente web integrado y nueva paridad funcional. La beta no autoriza pruebas contra sistemas de terceros.
