# Índice de parches sobre upstream (`vendor/`)

Este archivo registra todos los parches aplicados sobre el código base de upstream según las reglas de `AGENTS.md` §5.
Los parches se almacenan en este directorio (`patches/*.patch`) y se aplican mediante `tools/apply-patches`.

## Reglas para parches

1. **Un parche = un propósito** con ID de tarea y justificación.
2. No editar `vendor/` directamente sin crear y registrar el parche correspondiente.
3. Todo parche debe ser idempotente y poder aplicarse en orden numérico/alfabético mediante `tools/apply-patches`.
4. Preferir extensión (nuevos módulos, hooks, flags de configuración) sobre modificación de lógica existente.
5. Cada parche debe contener cabecera con metadatos: autor, fecha, tarea asociada y resumen.

---

## Registro de parches

| Archivo de parche | Tarea | Componente | Descripción | Archivos modificados | Fecha | Autor |
|---|---|---|---|---|---|---|
| *(Ninguno por ahora)* | - | - | - | - | - | - |

---

### Plantilla de registro para nuevos parches

Al añadir un parche, agregar una fila en la tabla superior y documentar la sección detallada abajo:

```markdown
### [NNN-slug.patch] Tarea <ID>: <Título del parche>

- **Archivo:** `patches/<NNN-slug>.patch`
- **Componente:** `vendor/server` | `vendor/client`
- **Tarea:** `<ID>`
- **Fecha:** `<YYYY-MM-DD>`
- **Autor/Rol:** `<Agente>`
- **Motivo / Justificación:** `<Por qué se requiere modificar upstream en lugar de extender>`
- **Archivos modificados:**
  - `<ruta/al/archivo>`
- **Estrategia de actualización (upstream sync):** `<Cómo conciliar este parche cuando se actualice la versión de upstream>`
```
