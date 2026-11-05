# AGENTS.md — Reglas de trabajo para agentes de Cercano

Este documento es obligatorio para todo agente que ejecute tareas.

## 1. Fuentes de verdad

1. `docs/ROADMAP.md`: qué se construye y en qué orden.
2. `docs/ARQUITECTURA.md`: cómo está diseñado y qué decisiones rigen.
3. `docs/PLAN-*.md`: tareas con ID, dependencias y criterios de aceptación.
4. `docs/PLAN-DE-PRUEBAS.md`: cómo se verifica.
5. `docs/status/TAREAS.md`: estado vivo de cada tarea. `docs/status/BLOCKERS.md`: bloqueos abiertos.
6. `branding/README.md`: uso del logo y la paleta.

Si algo contradice estos documentos, **se detiene la tarea y se reporta al Coordinador**; no se improvisa.

## 2. Roles

| Rol | Responsabilidad |
|---|---|
| **Coordinador** | Mantiene roadmap y planes, asigna tareas, resuelve dependencias, aprueba cierres de fase |
| **Agente-Servidor** | `server/`, hbbs/hbbr, packaging del servidor |
| **Agente-Cliente** | `client/`, parches al cliente, rebranding |
| **Agente-ControlPlane** | `control-plane/`, `audit-core/` |
| **Agente-Builder** | `builder/`, CI/CD, firma, empaquetado |
| **Agente-Web** | `console-web/` |
| **Agente-QA** | Escribe y ejecuta pruebas, mantiene el laboratorio LAN, verifica criterios de aceptación; **no verifica su propio código** |
| **Agente-Seguridad** | Revisión de seguridad por fase, modelo de amenazas, SAST/fuzzing |

Una tarea la ejecuta el rol indicado en el plan y la verifica un agente distinto (normalmente QA).

## 3. Ciclo de una tarea

1. **Tomar:** cambiar estado a `En curso` en `docs/status/TAREAS.md` y comprobar que las dependencias están `Hecho`.
2. **Rama:** `feat/<ID>-slug`, `fix/<ID>-slug` o `docs/<ID>-slug`.
3. **Implementar** dentro del alcance de la tarea. No tocar archivos ajenos al alcance.
4. **Probar** según los criterios de aceptación; añadir pruebas nuevas.
5. **PR** con la plantilla: ID de tarea, resumen, cambios en `vendor/` (si hay), pruebas ejecutadas, riesgos.
6. **Verificación** por un agente distinto: ejecuta las pruebas y rellena el informe.
7. **Cierre:** el Coordinador fusiona y marca `Hecho`.

Estados: `Pendiente` → `En curso` → `En verificación` → `Hecho`; también `Bloqueada` y `Diferida`.

## 4. Definición de «Hecho»

- Criterios de aceptación cumplidos y demostrados con evidencia (salida de pruebas, capturas, logs).
- `cargo fmt`, `cargo clippy -D warnings`, `cargo test` y `cargo deny check` en verde (para código Rust); lint y tests equivalentes en otros lenguajes.
- Documentación actualizada (README del componente, specs, ADR si aplica).
- Sin secretos en el repositorio.
- Parches a `vendor/` registrados en `patches/INDEX.md`.

## 5. Reglas sobre el código heredado (`vendor/`)

- No se edita `vendor/` directamente: los cambios se hacen como parches en `patches/` y se aplican con el script `tools/apply-patches`.
- Un parche = un propósito. Mensaje con ID de tarea y justificación.
- Preferir extensión (módulos nuevos, flags de configuración) sobre modificación.

## 6. Reglas legales (críticas)

- **Clean-room:** no se descargan, ejecutan, descompilan ni inspeccionan binarios de RustDesk Server Pro ni código de procedencia dudosa. Solo documentación pública y código abierto.
- **Licencia:** todo código nuevo lleva el encabezado AGPL-3.0; las dependencias nuevas deben ser compatibles. **No se importa código de upstream (`vendor/`) mientras el archivo `LICENSE` no sea el texto oficial de AGPL-3.0** (ver `docs/status/BLOCKERS.md`, B-001).
- **Marca:** no usar el nombre ni el logo de RustDesk en binarios, instaladores ni interfaz. Usar el logo de Cercano solo según `branding/README.md`.

## 7. Reglas de seguridad

- Sin secretos, claves ni certificados en el repositorio, en logs ni en artefactos; usar variables de entorno o gestor de secretos.
- Pruebas de seguridad (fuzzing, intentos de manipulación) solo contra el laboratorio LAN propio, nunca contra sistemas de terceros.
- Toda función que dé acceso remoto debe poder auditarse y desactivarse por política.
- Si se encuentra una vulnerabilidad: no publicarla en issues públicos; reportarla en `docs/status/SECURITY-PRIVADO.md` y avisar al Coordinador.

## 8. Comunicación

**Informe de tarea** (al cerrar o al bloquearse), en el PR o en `docs/status/informes/<ID>.md`:

```
ID: <tarea>      Agente: <rol>      Estado: <Hecho|Bloqueada|Diferida>
Qué se hizo:      <2–4 líneas>
Evidencia:        <comandos y resultados de pruebas>
Desviaciones:     <cambios respecto al plan, o «ninguna»>
Riesgos / deuda:  <o «ninguno»>
Siguiente paso sugerido: <opcional>
```

**Bloqueos:** registrar en `docs/status/BLOCKERS.md` con ID, causa y qué se necesita. No esperar en silencio.

**Convenciones:** Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`), mensajes en español o inglés pero consistentes por PR; código e identificadores en inglés; documentación en español.

## 9. Qué hacer ante la duda

1. Releer el plan y la arquitectura.
2. Si sigue habiendo ambigüedad menor, elegir la opción más segura y reversible, y anotarla en el informe.
3. Si afecta al diseño, la seguridad o la licencia, detenerse y escalar al Coordinador.
