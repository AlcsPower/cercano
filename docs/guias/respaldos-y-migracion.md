# Guía — Respaldos y migración de base de datos

**Versión:** 0.1 · **Fecha:** 2026-11-10 · **Aplica a:** operadores de Cercano (F1 en adelante).
**Diseño:** [ADR-011](../adr/011-portabilidad-bd.md) y [specs/db-portabilidad.md](../specs/db-portabilidad.md).

> **Estado de esta guía.** Las secciones 2–4 funcionan **hoy** con el despliegue actual (SQLite). Las secciones 5–8 describen la operación que habilitan F8-06, F8-07 y F8-08; hasta que esas tareas estén cerradas, la pestaña «Mantenimiento» no existe y hay que usar el procedimiento manual.

## 1. Qué se respalda y qué no

| Elemento | Ruta | Respaldo | Notas |
|---|---|---|---|
| Base de datos | `/opt/cercano/data/cercano.db` (+ `-wal`, `-shm`) | **Obligatorio** | Copiar en caliente exige `sqlite3 .backup`; `cp`/`tar` deja copia inconsistente |
| Adjuntos de chat | `/opt/cercano/data/chat-attachments/` | Recomendado | Metadatos en la BD; los binarios no |
| Clave de firma de auditoría | `/opt/cercano/data/audit_signing_key` | **Obligatorio para verificar** | Sin ella no se pueden verificar checkpoints ya emitidos |
| Claves del servidor | `/opt/cercano/data/id_ed25519` y `.pub` | **Obligatorio** | Rotables, pero los clientes con la clave vieja dejan de conectar |
| Artefactos de build | `CERCANO_BUILDS_DIR` | Opcional | Regenerables |
| Configuración | `cercano.toml` / variables | Recomendado | Contiene el token interno: trátese como secreto |

El respaldo de la consola (F8) cubre **solo la BD** y, opcionalmente, los adjuntos. **Las claves nunca están en ese archivo**: se respaldan aparte (§3). Un respaldo sin claves restaura el servicio, pero no permite verificar checkpoints antiguos.

## 2. Respaldo manual (hoy)

```bash
set -euo pipefail
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT=/mnt/backups/cercano/$TS
mkdir -p "$OUT" && chmod 700 "$OUT"

# 1. BD con copia consistente en caliente (no copiar el .db a mano)
sqlite3 /opt/cercano/data/cercano.db ".backup '$OUT/cercano.db'"
sqlite3 "$OUT/cercano.db" "PRAGMA integrity_check;"   # debe imprimir: ok

# 2. Adjuntos (si el chat está habilitado)
tar -czf "$OUT/chat-attachments.tar.gz" -C /opt/cercano/data chat-attachments 2>/dev/null || true

# 3. Claves y configuración
tar -czf "$OUT/claves-y-config.tar.gz" -C /opt/cercano/data \
  audit_signing_key id_ed25519 id_ed25519.pub 2>/dev/null || true

chmod 600 "$OUT"/*
echo "Respaldo: $OUT"
```

- Ejecutar diario con un `systemd` timer o cron; **medir la duración** y no hacerlo coincidir con la ventana de builds.
- Retención mínima sugerida: 30 copias. Conservar la más antigua del trimestre.
- Verificar una copia al mes restaurándola en un entorno de pruebas (§4). Un respaldo sin restauración probada no es un respaldo.

## 3. Copia fuera del equipo

```bash
gpg --symmetric --cipher-algo AES256 -o "$OUT.tar.gz.gpg" - < <(tar -czf - -C "$OUT" .)
```

Guardar la frase de paso **fuera** del servidor (gestor de secretos) y el archivo en un medio distinto del disco de la base. Nada de respaldos en claro en unidades compartidas ni en repositorios.

## 4. Restauración manual (hoy)

1. Detener `cercano-api`: `systemctl stop cercano-api` (o `docker compose stop cercano-api`).
2. Respaldar el estado actual antes de tocar nada: renombrar `cercano.db`, `-wal` y `-shm`.
3. Copiar el respaldo a `/opt/cercano/data/cercano.db`; **sin** los archivos `-wal`/`-shm` viejos.
4. Verificar: `sqlite3 /opt/cercano/data/cercano.db "PRAGMA integrity_check;"` → `ok`.
5. Permisos: `chown cercano:cercano` y `0600`.
6. Arrancar y comprobar `GET /healthz` → `200` y `status: ok`.
7. Verificar la cadena con `cercano-audit verify` sobre la BD restaurada; un fallo aquí invalida la restauración (no arrancar en producción).
8. Revisar que hay usuarios, dispositivos y un evento de auditoría reciente; probar un login y un latido.

**Rollback:** el archivo renombrado en el paso 2 es el rollback inmediato. No se borra hasta 24 h después de validar.

## 5. Respaldo desde la consola (F8-06)

1. Pestaña **Mantenimiento** → *Crear respaldo*. Opción «incluir adjuntos».
2. La copia se firma con la clave de auditoría; la lista muestra estado, tamaño, versión de esquema y `verified_at`.
3. *Verificar* recalcula firma y hashes; un fallo indica tabla y fila y no invalida las copias anteriores.
4. *Descargar* deja el archivo con `no-store`; la descarga queda auditada (`db.backup_downloaded`).
5. Programación: intervalo y número de copias en la misma pestaña. La primera copia automática ocurre un intervalo después del arranque.
6. La retención nunca borra la copia más reciente ni la única verificada.

## 6. Restauración desde la consola (F8-06)

Requisitos: rol `admin`, reautenticación (contraseña) y confirmación tipada del motor de origen.

1. Subir el archivo (y el de adjuntos si existe).
2. La consola verifica firma, hashes, versión de esquema y correspondencia de tablas **antes** de escribir.
3. Se crea un snapshot del estado actual, obligatorio.
4. La restauración se aplica en un esquema temporal, se comparan conteos y se verifica la cadena.
5. Solo entonces se intercambia y se informa el resultado.

Si algo falla en 2–4, la base actual no se modifica. Un fallo en el intercambio deja el snapshot y el código de error (`db.restore_failed`).

## 7. Migración a PostgreSQL (F8-07)

**Antes de la ventana**

- PostgreSQL 14 o superior, con una base vacía y un usuario con permiso de crear esquema.
- Conectividad desde `cercano-api` al destino, incluido TLS si es remoto; probar con `preflight`.
- Espacio en disco ≥ 2× el tamaño de la BD; ventana anunciada (la escritura se corta).
- Respaldo firmado reciente y copia de claves a mano.

**Durante la ventana**

1. `POST /api/db/migration/preflight` con la cadena destino: comprueba destino vacío, versión, permisos, espacio y estima filas y duración.
2. `POST /api/db/migration`: el servicio entra en **mantenimiento** (escrituras `503`, lecturas permitidas), toma el snapshot y copia por lotes con checksums.
3. La consola muestra tabla y filas copiadas; el proceso se puede abandonar con *rollback* mientras esté en `copying` o `verifying`.
4. Verificación: conteos, fingerprint de esquema y `cercano-audit verify` sobre el destino.
5. Corte: la API escribe `database_url` en el TOML (atómico, `0600`) y responde `requires_restart: true`.

**Después**

1. Reiniciar `cercano-api`; `GET /api/db/status` debe informar `engine: postgres`.
2. Repetir las comprobaciones del §4, pasos 6–8 (login, latido, evento reciente, cadena en verde).
3. Mantener el `cercano.db` original al menos 7 días: es el rollback hasta que la operación se valide.

**Qué no cambia:** adjuntos y claves siguen en `/opt/cercano/data`. **Qué se degrada durante la ventana:** chat, builds y latidos (los equipos pasan a `offline` tras 60 s y vuelven solos). Las sesiones remotas activas no dependen del control plane y continúan.

## 8. Migración a SQL Server (condicionada)

Solo si F8-01 aprueba el driver. El procedimiento es idéntico al §7 con `sqlserver://` como destino y estas diferencias: base y usuario creados de antemano, `BULK INSERT` disponible si la copia es lenta, y confirmación del orden de colación para las comparaciones de texto. Si F8-01 no lo aprueba, la operación no se ofrece en la consola y esta sección se retira.

## 9. Diagnóstico

| Síntoma / código | Causa probable | Acción |
|---|---|---|
| `db.reauth_required` | Token de 60 s expirado | Repetir la reautenticación |
| `db.job_in_progress` | Otro respaldo/migración en curso | Esperar; un solo trabajo a la vez |
| `db.backup_invalid_signature` | Archivo alterado o clave distinta | Descartar el archivo; usar otra copia |
| `db.backup_schema_newer` | Respaldo de una versión más nueva del binario | Actualizar `cercano-api` o usar copia anterior |
| `db.storage_full` | Sin espacio | Liberar espacio; el `.tmp` se puede borrar |
| `db.migration_preflight_failed` | Destino ocupado, sin permisos o inaccesible | Corregir y repetir el preflight |
| `db.migration_cutover_failed` | No se pudo escribir el TOML | El servicio sigue en el origen; corregir permisos y repetir |
| Equipos `offline` tras la ventana | Latidos rechazados durante mantenimiento | Se recuperan en el siguiente latido (≤ 15 s) |

## 10. Checklist de cierre de una operación

- [ ] `GET /api/db/status` informa el motor esperado y el esquema correcto.
- [ ] `PRAGMA integrity_check` (SQLite) o `pg_dump --schema-only` sin error (PostgreSQL).
- [ ] `cercano-audit verify` en verde sobre la base en uso.
- [ ] Login de un administrador y un operador.
- [ ] Un dispositivo pasa a `online` en ≤ 60 s.
- [ ] Evento `db.*` de la operación presente en la auditoría.
- [ ] Copia de claves fechada y guardada fuera del servidor.
- [ ] Respaldo original conservado según la política (7 días tras una migración).
