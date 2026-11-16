# ADR-012 — Grupos, estrategias centrales y federación de identidad (F5)

- **Estado:** Aprobado (2026-11-16) por Dueño del producto, Coordinador y Agente-Seguridad.
- **Fecha:** 2026-11-10 (Aprobado: 2026-11-16)
- **Fase:** F5
- **Decisores:** Dueño del producto, Coordinador, Agente-ControlPlane, Agente-Seguridad
- **Relacionados:** [`docs/specs/identidad.md`](../specs/identidad.md) (contrato), [`docs/PLAN-F5-IDENTIDAD.md`](../PLAN-F5-IDENTIDAD.md) (tareas), [`docs/adr/008-roles-instalador.md`](008-roles-instalador.md) (roles de instalador, no se tocan), [`docs/specs/cercano-profile.md`](../specs/cercano-profile.md) (perfil firmado), [`docs/specs/audit-events.md`](../specs/audit-events.md)

## 1. Contexto

F4 dejó roles fijos y 2FA; F5 añade alcance por grupo, estrategias centrales y proveedores de
identidad. Lo que hoy no existe y este ADR fija:

- No hay forma de acotar qué dispositivos ve un operador: `devices:read` es global.
- La política vive en el perfil firmado del instalador; cambiarla exige regenerar el instalador.
- No hay grupo, libreta ni federación: cada despliegue con directorio corporativo queda fuera.

Restricciones que mandan sobre el diseño: negación por defecto; la autorización se calcula y aplica
en el servidor (ocultar en la consola no cuenta); el perfil firmado es el techo y ninguna política
central lo amplía; toda lectura y escritura se limita por rol, pertenencia y alcance; y el contrato
de roles de instalador (ADR-008) no cambia.

## 2. Decisiones

1. **Grupos como único ámbito.** `groups` con `kind` `user` o `device`, membresía N:M y **concesiones
   explícitas entre grupos** (`read`/`operate`). Sin concesión no hay acceso: un operador solo ve los
   dispositivos de sus grupos y los de los grupos a los que sus grupos tienen concesión. `admin`
   sigue viendo todo; `auditor` no ve libreta ni obtiene `operate`. Ver spec §3.
2. **Libreta operativa, sin secretos.** Entradas con nombre, dispositivo o grupo, etiquetas y datos de
   conexión; nunca claves, tokens ni credenciales. La visibilidad usa las mismas concesiones que los
   dispositivos. Un `operator` puede leer y usar la libreta; crear y borrar entradas es de `admin` en
   v1.
3. **Estrategias versionadas y explicables.** Documento JSON inmutable con `scope_type`
   (`global`/`group`/`device`), versión incremental y estado (`draft`/`active`/`superseded`/`revoked`).
   Una sola versión activa por ámbito. La resolución es determinista y se explica clave por clave
   (qué valor, de qué ámbito y por qué regla). Ver spec §4.
4. **Precedencia con el perfil como techo.** Orden: perfil firmado (P0) → global (P1) → grupo (P2) →
   dispositivo (P3). Para claves de seguridad gana el valor **más restrictivo**; para escalares gana
   el ámbito **más específico**; entre grupos empatados gana el más restrictivo y, si persiste el
   empate, el `group_id` menor. Nunca se amplía P0. Una política caducada, revocada, malformada o con
   hash que no coincide se trata como ausente: deniega, no concede.
5. **Enforcement en el servidor, caché en el cliente.** El cliente descarga la política efectiva, la
   cachea con TTL (300 s por defecto, máximo 3600 s) y la aplica; sin red usa la última copia vigente y
   si caducó **falla cerrado** para conexiones nuevas. El cliente no puede editar ni elevar la
   política; el perfil firmado se sigue verificando en cada arranque.
6. **OIDC con Authorization Code + PKCE.** `state` y `nonce` de un solo uso, URI de retorno exacta,
   validación de emisor, audiencia, firma y rotación de claves, y sesión solo tras validar. La
   identidad se ancla en **issuer + subject**, nunca en correo ni nombre de usuario. La vinculación es
   explícita (admin o el propio usuario reautenticado); no hay vinculación automática por correo.
7. **LDAP como alternativa, sobre TLS obligatorio.** `ldaps://` o StartTLS con validación de
   certificado; bind de servicio para buscar, bind del usuario para autenticar; filtros escapados
   (RFC 4515); tiempos límite; errores genéricos que no revelan si la cuenta existe; mapeo de grupos
   por **allowlist** (`DN de directorio → rol de Cercano`), con rol por defecto `auditor` o denegación.
8. **2FA de Cercano sigue mandando.** Ni LDAP ni OIDC sustituyen al TOTP salvo que el administrador
   configure el proveedor como garante de MFA (`acr`/`amr` comprobados en el token). La elevación con
   credenciales (F3-16) y cualquier consulta LAPS futura exigen 2FA verificado por Cercano.
9. **Cuenta break-glass local.** Un administrador local con contraseña + TOTP sigue disponible aunque
   se configure SSO; ningún ajuste de proveedor lo desactiva. Su uso se audita y la consola avisa.
   La recuperación de identidad (códigos, desvinculación) tiene procedimiento documentado en F5-13.
10. **Migración 009, aditiva.** Siete tablas nuevas, sin tocar las existentes ni `audit_events`. DDL
    portable (sin `datetime('now')`, `strftime` ni `AUTOINCREMENT`) porque F8 porta el esquema. Si
    F6-02 llegara antes, el Coordinador fija el orden y F5 toma el siguiente número libre.
11. **Cambio de ID de dispositivo: diferido.** No se implementa en F5 (F5-09 redacta el ADR de
    diferimiento). El ID es el ancla de sesiones, historial de auditoría, perfil de instalador y
    autenticación de chat; cambiarlo sin tombstone, historial y aprobación explícita abre suplantación
    y rompe referencias. Se revisa solo si aparece una necesidad operativa real.
12. **Windows LAPS: diferido.** Sin bóveda propia, el secreto tendría que entregarse de forma efímera,
    con consentimiento, permiso dedicado y 2FA; hoy no hay esa ruta en el cliente y el tecleo manual de
    F3-16 cubre la necesidad. F5-10 redacta el ADR de diferimiento; se revisa si un cliente lo exige y
    Seguridad aprueba el flujo.

## 3. Consecuencias

**Positivas**

- Un operador deja de ver todo el parque: el alcance por grupo es el mínimo privilegio que faltaba.
- La política se cambia sin regenerar instaladores, y sigue sin poder ampliar el perfil firmado.
- Un cliente con directorio corporativo puede entrar por OIDC o LDAP sin renunciar a la 2FA.
- La política efectiva es explicable: cualquier denegación se puede justificar con su fuente.

**Negativas y riesgos**

- **Superficie de autorización nueva.** Grupos, concesiones y libreta añaden rutas que hay que probar
  contra IDOR y escalada; se mitiga con matriz rol × operación × ámbito y pruebas negativas (F5-12).
- **Complejidad de precedencia.** Un error de resolución puede debilitar políticas; se mitiga con
  reglas formales, deny-by-default y casos de propiedad en el catálogo.
- **Dependencia de IdP/directorio.** Una caída deja fuera a los usuarios federados; se mitiga con
  tiempos límite, sesiones vigentes que no se cortan y break-glass documentado.
- **Migraciones concurrentes.** F5, F6 y F8 comparten secuencia; el orden lo fija el Coordinador.
- **Dos caminos de login.** Cada proveedor añade validaciones que hay que probar por separado.

## 4. Alternativas consideradas

| Alternativa | Por qué se descarta |
|---|---|
| Permisos por usuario en lugar de grupos | Multiplica filas y no escala; el grupo es la unidad que el cliente ya entiende (perfil `device_group`). |
| Política solo en el perfil firmado | Obliga a regenerar instaladores por cada cambio de política; F5 existe para evitarlo. |
| Precedencia con el ámbito más específico siempre | Permitiría que un grupo o dispositivo amplíe una restricción global; rompe el principio de que lo restrictivo gana. |
| Vincular identidades por correo | Convierte un correo reasignado o no verificado en toma de cuenta. |
| OIDC o LDAP como sustituto de la 2FA | Deja cuentas sin segundo factor si el proveedor no garantiza MFA; el invariante de F4 lo prohíbe. |
| Cambiar el ID de dispositivo en F5 | Rompe auditoría, sesiones y autenticación de chat sin mecanismo de tombstone; se difiere. |
| Bóveda propia de credenciales LAPS | Duplica un gestor de secretos y contradice el alcance de F5; se difiere. |

## 5. Referencias

- Contrato detallado (tablas, permisos, resolución, proveedores, API): [`docs/specs/identidad.md`](../specs/identidad.md).
- Plan y criterios de aceptación: [`docs/PLAN-F5-IDENTIDAD.md`](../PLAN-F5-IDENTIDAD.md).
- Casos de prueba: [`docs/PLAN-DE-PRUEBAS.md`](../PLAN-DE-PRUEBAS.md) §6 «F5».
