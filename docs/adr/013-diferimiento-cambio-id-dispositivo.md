# ADR-013 — Diferimiento del cambio de ID de dispositivo (F5-09)

- **Estado:** Aprobado (2026-11-16) por Coordinador, Agente-Servidor y Agente-Seguridad.
- **Fecha:** 2026-11-16
- **Fase:** F5
- **Decisores:** Dueño del producto, Coordinador, Agente-Servidor, Agente-ControlPlane, Agente-Seguridad
- **Relacionados:** [`docs/specs/identidad.md`](../specs/identidad.md), [`docs/PLAN-F5-IDENTIDAD.md`](../PLAN-F5-IDENTIDAD.md), [`docs/adr/012-identidad-grupos-federacion.md`](012-identidad-grupos-federacion.md), [`docs/specs/cercano-profile.md`](../specs/cercano-profile.md), [`docs/specs/chat-seguro.md`](../specs/chat-seguro.md), [`docs/specs/audit-events.md`](../specs/audit-events.md)

---

## 1. Contexto

Durante el diseño de la Fase 5 (Identidad y Control de Acceso), se evaluó la conveniencia de permitir a los operadores o a los propios clientes remotos modificar su `device_id` asignado (por ejemplo, ante clonación de máquinas virtuales, reemplazo de hardware o reorganización de inventario).

En Cercano, el `device_id` actúa como el ancla primaria de:
1. **Identidad criptográfica y perfil firmado (F3):** El instalador firmado (`installer_id`, perfil P0) y las credenciales locales vinculan las capacidades autorizadas al identificador del equipo.
2. **Autenticación y sesiones de soporte:** La validación de heartbeats (`devices`), asignación de políticas (`policies`) y pertenencia a grupos (`group_members`, `address_book`).
3. **Autenticación y canales de chat seguro (F4.5):** La clave pública Ed25519 del dispositivo autentica los mensajes y eventos de chat vinculados a su `device_id`.
4. **Cadena de custodia de auditoría (F1/F2/F4):** Los registros inmutables en `audit_events` referencian al `device_id` como actor o sujeto en conexiones, elevaciones y transferencias de archivos.

---

## 2. Modelo de Amenazas del Cambio de ID

La modificación arbitraria o asistida del `device_id` introduce vectores de ataque críticos que debilitan la seguridad del sistema:

1. **Apropiación y suplantación del ID anterior:** Si un dispositivo cambia su ID sin un mecanismo transaccional de tombstone (lápida inmutable), un atacante en la red podría registrar un nuevo equipo adoptando el ID liberado, heredando accesos, historial de libreta de direcciones y políticas previas.
2. **Ruptura de la cadena forense y auditoría:** `audit_events` es una base de datos inmutable y criptográficamente sellada (HMAC/Ed25519). Si un dispositivo transmuta su identificador, las consultas forenses pierden la correlación histórica continua entre el dispositivo físico y los eventos previos, a menos que se mantenga un grafo complejo de linaje de identidades.
3. **Incompatibilidad con perfiles sellados:** Permitir al cliente alterar su `device_id` contradice la regla de invariancia de P0 (el cliente no puede alterar su propia configuración ni elevar sus privilegios locales).
4. **Colisión maliciosa y denegación de servicio:** Un cliente comprometido podría solicitar un cambio de ID hacia el ID de un servidor crítico o estación de soporte, causando colisión de clave pública y denegación de servicio en el rendezvous/relay (F6).

---

## 3. Decisión

**Se difiere formalmente el cambio de ID de dispositivo.** En Cercano v1, el `device_id` es **estrictamente inmutable** durante todo el ciclo de vida del equipo.

Reglas aplicadas:
1. **Sin rutas ni permisos nuevos (TC-F5-050):** No se implementan endpoints en el control plane (`PUT/PATCH /api/devices/{id}/change-id`), ni permisos de mutación de identificador en el cliente o servidor.
2. **Procedimiento ante clonación o reemplazo:** Cuando una máquina virtual es clonada o un equipo es reemplazado:
   - El equipo clonado/nuevo debe ejecutar un aprovisionamiento limpio generando un nuevo `device_id` y par de claves mediante un instalador oficial.
   - El equipo desincorporado se marca como inactivo o se elimina de la consola por un administrador mediante `DELETE /api/devices/{id}` (lo que revoca sus claves y desvincula sus sesiones activas de forma auditable).
3. **Criterio de reapertura:** Esta decisión solo se reconsiderará en fases futuras si surge un requisito estricto de soporte a gran escala que no pueda resolverse con re-aprovisionamiento, y solo si se diseña un esquema formal de linaje con firmas criptográficas de transición y registro tombstone en el registro de auditoría.

---

## 4. Consecuencias

### Positivas
- **Máxima simplicidad y fiabilidad (YAGNI / Ponytail):** Cero código complejo de migración de ID, sin tablas auxiliares de alias ni reconciliación de claves.
- **Integridad forense intacta:** Las referencias en `audit_events`, `chat_conversations`, `group_members` y `policies` permanecen unívocas y libres de ambigüedad.
- **Sin superficie de ataque adicional:** Imposibilidad de suplantación de ID por reasignación dinámica.

### Negativas
- En escenarios de clonación descontrolada de imágenes de disco sin sysprep/limpieza de Cercano, los operadores deberán desinstalar y reinstalar el cliente para generar un nuevo ID unívoco.
