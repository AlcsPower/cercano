# ADR-008 — Roles de instalador: perfil y aplicación en el servidor

- **Estado:** Aceptado
- **Fecha:** 2026-11-10
- **Fase:** F3 (Generador de instaladores personalizados)
- **Decisores:** Coordinador, Agente-ControlPlane, Agente-Servidor, Agente-Seguridad
- **Relacionados:** [`docs/ARQUITECTURA.md`](../ARQUITECTURA.md), [`docs/PLAN-F3-GENERADOR.md`](../PLAN-F3-GENERADOR.md), [`docs/specs/cercano-profile.schema.json`](../specs/cercano-profile.schema.json), [`docs/specs/audit-events.md`](../specs/audit-events.md)

## 1. Contexto

El modelo operativo de Cercano define dos tipos de instaladores con propósitos y superficies de ataque radicalmente distintos:

1. **Cercano Soporte (`role: "soporte"`):** destinado a los puestos de trabajo de personas usuarias que reciben asistencia. Está diseñado para recibir conexiones con consentimiento explícito y jamás debe poder iniciar sesiones remotas hacia otros puestos ni solicitar elevación de privilegios administrativos.
2. **Cercano Técnico (`role: "tecnico"`):** destinado exclusivamente al personal autorizado del área de TI para brindar soporte, administrar dispositivos y realizar intervenciones técnicas previa autenticación en `cercano-api`.

En soluciones tradicionales de acceso remoto, las diferencias entre el cliente de soporte y el cliente técnico residen frecuentemente en configuraciones locales o flags de compilación en el endpoint. Esta aproximación presenta un riesgo de seguridad crítico: si un usuario o adversario modifica la configuración local en el registro de Windows, parchea binarios en memoria o manipula el tráfico HTTP/gRPC hacia el servidor, un cliente concebido como `soporte` podría comportarse como `tecnico` e iniciar conexiones salientes o propagar elevaciones no autorizadas en la red corporativa (amenaza documentada en el modelo de amenazas de `ARQUITECTURA.md` como «Escalada de soporte a técnico»).

## 2. Decisión

Se adopta el principio rector: **«El rol se aplica en el servidor, no solo en el instalador»**.

1. **Inclusión criptográfica en el perfil:** El rol (`soporte` o `tecnico`) y el identificador único del instalador (`installer_id`) forman parte obligatoria del perfil JSON firmado con Ed25519 por el servicio generador (`cercano-build` / `cercano-api`).
2. **Registro canónico en la base de datos:** Cada generación de instalador se almacena en `build_jobs` con su `id` (`installer_id`) y su `role`.
3. **Asociación inmutable en el registro del dispositivo:** Al emitir el primer heartbeat o registro (`POST /api/devices/heartbeat`), el servidor consulta el `installer_id` en `build_jobs`, determina el rol canónico y lo asocia de forma **inmutable** en la tabla `devices`. Una vez persistido, ningún latido o petición posterior puede modificar el `installer_id` ni mutar el `role` del dispositivo en la base de datos.
4. **Detección inmediata de suplantación (*tampering*):** Si un cliente envía una petición o latido pretendiendo operar como `tecnico` (vía payload JSON o cabeceras HTTP como `X-Client-Role: tecnico`) cuando su `installer_id` o registro en el servidor corresponde a `soporte`, el servidor:
   - Rechaza la petición de inmediato con código **HTTP 403 Forbidden** y cuerpo `{ "error": "role_violation", ... }`.
   - Dispara una alarma de seguridad estructurada en `AlarmEngine`: `alarm.role_violation` con severidad `critical`.
   - Registra un evento de denegación encadenado criptográficamente en el registro de auditoría (`audit_core`).
5. **Control de acceso y denegación por defecto en operaciones técnicas:**
   - Toda operación técnica restringida —incluyendo iniciar conexión remota saliente (`POST /api/sessions/initiate`), solicitar o enviar elevación de privilegios de administrador (`POST /api/elevation/request`), o aplicar modificaciones de políticas restringidas del servidor (`POST /api/policies/apply`)— verifica el rol registrado del dispositivo y del instalador en el servidor.
   - Si el rol es `soporte`, la operación se deniega incondicionalmente con HTTP 403 Forbidden (`role_violation`), registrando la alarma `alarm.role_violation` y el evento de auditoría correspondiente con resultado `Denied`.
   - Para roles `tecnico`, el servidor valida adicionalmente que el instalador no se encuentre revocado ni caducado (`RevocationChecker`).

## 3. Consecuencias

**Positivas:**
- **Inmunidad ante manipulación local:** Modificar la configuración local del cliente, falsear cabeceras de red o manipular binarios no permite a un cliente `soporte` obtener privilegios técnicos ni iniciar conexiones salientes.
- **Trazabilidad y detección proactiva:** Cualquier intento de escalada o manipulación genera una alarma crítica en el `AlarmEngine`, alertando al equipo de seguridad de forma inmediata y persistiendo evidencia forense inmutable en `audit_core`.
- **Defensa en profundidad:** El cliente aplica restricciones de interfaz (F3-14), pero la seguridad descansa en la verificación autoritativa del plano de control en el servidor.

**Negativas y mitigaciones:**
- **Dependencia de la base de datos de control:** El servidor debe validar el rol en cada operación crítica. Mitigado mediante índices optimizados en SQLite (`idx_devices_role`, `idx_build_jobs_role`) y tiempos de respuesta submilisegundos en la LAN.
- **Gestión de ciclo de vida:** Si un equipo legítimamente necesita ser reasignado de rol `soporte` a `tecnico`, requiere una reinstalación autorizada con un nuevo instalador y el restablecimiento administrativo auditado del dispositivo.

## 4. Alternativas consideradas

| Alternativa | Razón de descarte |
|---|---|
| Confianza exclusiva en el cliente | Violación directa de los principios de seguridad de Cercano: el cliente se ejecuta en endpoints no confiables y puede ser manipulado. |
| Rol derivado únicamente de la cuenta de usuario | Insuficiente: un técnico con cuenta legítima podría iniciar sesión desde un endpoint de soporte inseguro, violando la segregación de entornos. Ambos (dispositivo y cuenta) deben cumplir los requisitos. |
| Validación en servidor solo por token sin persistir rol en `devices` | Incrementa la complejidad de cada petición y no garantiza la inmutabilidad histórica del dispositivo auditado. |

## 5. Referencias

- [`docs/ARQUITECTURA.md`](../ARQUITECTURA.md) — Modelo de amenazas: amenaza «Escalada de soporte a técnico».
- [`docs/PLAN-F3-GENERADOR.md`](../PLAN-F3-GENERADOR.md) — Sección 1 («El rol se aplica en el servidor, no solo en el instalador») y Tarea F3-13.
- [`docs/specs/audit-events.md`](../specs/audit-events.md) — Categorías `alarm` y `auth`, acción `alarm.role_violation`.
