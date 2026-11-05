<p align="center">
  <img src="branding/logo/cercano-wordmark-light.svg" alt="Cercano" height="72">
</p>

<p align="center"><em>Soporte remoto, como si estuvieras ahí.</em></p>

# Cercano

Aplicación de soporte remoto para equipos de TI: **auditable**, **segura por defecto** y **optimizada para redes LAN**. Es un fork de [RustDesk](https://github.com/rustdesk/rustdesk) y [RustDesk Server](https://github.com/rustdesk/rustdesk-server) que añade, como código abierto, lo que el proyecto original reserva a su edición de pago: sobre todo **auditoría y trazabilidad** de extremo a extremo y un **generador de instaladores personalizados**.

> **Estado: fase 0 (fundación).** Todavía no hay código ejecutable ni versiones. Este repositorio contiene el plan de trabajo, la arquitectura y la marca. Sigue el avance en [`docs/status/TAREAS.md`](docs/status/TAREAS.md).

## Qué se propone construir

| Capacidad | Descripción |
|---|---|
| Auditoría con integridad verificable | Cada sesión, transferencia de archivos, intento fallido y acción administrativa queda registrada en una cadena de hashes con checkpoints firmados; se puede verificar sin conexión al servidor. |
| Traza extremo a extremo | Un `trace_id` une los eventos del cliente, el servidor y la API de una misma sesión. |
| Generador de instaladores | A partir de un perfil (servidor, clave, política, identidad visual) produce instaladores firmados, auditados y revocables. |
| Optimización para LAN | Conexión directa y relay local, sin depender de internet. |
| Exportación a SIEM | Syslog, CEF, JSONL y webhooks. |

El mapa completo de funciones y fases está en el [roadmap](docs/ROADMAP.md).

## Documentación

| Documento | Para qué sirve |
|---|---|
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Visión, paridad con la edición de pago, fases, riesgos y decisiones pendientes |
| [`docs/ARQUITECTURA.md`](docs/ARQUITECTURA.md) | Componentes, ADR, modelo de auditoría, modelo de amenazas, límites legales |
| [`docs/PLAN-F0-F1.md`](docs/PLAN-F0-F1.md) | Tareas de fundación y núcleo |
| [`docs/PLAN-F2-AUDITORIA.md`](docs/PLAN-F2-AUDITORIA.md) | Tareas de auditoría y traza |
| [`docs/PLAN-F3-GENERADOR.md`](docs/PLAN-F3-GENERADOR.md) | Tareas del generador de instaladores |
| [`docs/PLAN-DE-PRUEBAS.md`](docs/PLAN-DE-PRUEBAS.md) | Estrategia de pruebas, laboratorio LAN y casos |
| [`docs/status/TAREAS.md`](docs/status/TAREAS.md) | Estado de cada tarea |
| [`docs/status/BLOCKERS.md`](docs/status/BLOCKERS.md) | Bloqueos abiertos |
| [`branding/README.md`](branding/README.md) | Logo, paleta y reglas de uso de la marca |
| [`AGENTS.md`](AGENTS.md) | Reglas de trabajo para agentes y colaboradores |

## Estructura del repositorio

```
cercano/
├── AGENTS.md  CONTRIBUTING.md  SECURITY.md  NOTICE  LICENSE  README.md
├── branding/       logo, iconos y guía de marca
├── docs/           roadmap, planes, ADR, spikes, especificaciones, estado
├── vendor/         código de RustDesk importado (pendiente: F0-02)
├── patches/        parches de Cercano sobre vendor/
├── client/  server/  control-plane/  audit-core/  builder/  console-web/
├── deploy/  tests/  tools/
└── .github/        plantillas y CODEOWNERS
```

## Licencia

Cercano se distribuye bajo **GNU Affero General Public License v3.0 (AGPL-3.0)**. Consulta el archivo [`LICENSE`](LICENSE) para ver los términos completos. La atribución a los proyectos originales de los que deriva se encuentra en [`NOTICE`](NOTICE).

Cercano no está afiliado a RustDesk ni cuenta con su respaldo.

## Contribuir y reportar vulnerabilidades

Lee [`CONTRIBUTING.md`](CONTRIBUTING.md). Para vulnerabilidades, sigue [`SECURITY.md`](SECURITY.md); no abras issues públicos.
