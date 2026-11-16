# Guía de Operación: Identidad, Políticas y Recuperación de Emergencia

Este documento detalla los procedimientos de administración de identidad, gestión de grupos, libreta de direcciones, estrategias centrales y protocolos de recuperación ante incidentes en Cercano (Fase 5).

---

## 1. Modelo de Identidad y Control de Acceso

Cercano implementa un modelo de control de acceso basado en roles (RBAC) con alcance extendido por membresías de grupos (N:M) y políticas jerárquicas declarativas.

### 1.1 Roles del Sistema

| Rol | Alcance | Capacidades |
|---|---|---|
| **admin** | Global | Gestión total de usuarios, grupos, políticas, IdPs, auditoría y personalización. |
| **operator** | Grupos asignados | Gestión de sesiones remotas y chat con dispositivos de sus grupos o grupos con concesión `operate`. |
| **auditor** | Global (solo lectura) | Inspección de registros de auditoría y configuración de políticas; sin permisos de mutación. |
| **user** | Restringido | Acceso de cliente final a soporte remoto. |

### 1.2 Grupos y Concesiones (Grants)

- **Grupos de Usuarios (`kind: 'user'`):** Agrupan técnicos y operadores por departamento o nivel de soporte.
- **Grupos de Dispositivos (`kind: 'device'`):** Agrupan equipos por sede, criticidad o función.
- **Concesiones Cruzadas (`group_grants`):**
  - Permiso `read`: Otorga visibilidad del grupo y libreta de direcciones sin facultades operativas.
  - Permiso `operate`: Permite iniciar soporte remoto y mensajería segura con los dispositivos del grupo de destino.
  - La pertenencia a grupos **nunca eleva el rol** base del usuario (principio de mínimo privilegio).

---

## 2. Estrategias Centrales y Jerarquía de Precedencia

Cercano aplica una jerarquía estricta y determinista de 4 niveles para resolver la configuración efectiva en cada sesión:

```
[ P0: Perfil Firmado (Techo Infranqueable) ]
                    ↓
[ P1: Política Central de Dispositivo ]
                    ↓
[ P2: Política Central de Usuario / Grupo ]
                    ↓
[ P3: Preferencias Locales del Cliente ]
```

### Reglas de Resolución:
1. **Techo P0:** Ninguna política P1, P2 o preferencia local P3 puede habilitar una función deshabilitada en el perfil firmado P0 (por ejemplo, `allow_terminal` o `allow_file_transfer`).
2. **Conflicto entre Grupos:** Si un usuario o dispositivo pertenece a múltiples grupos con valores opuestos para una regla booleana, **prevalece el valor más restrictivo (`false`)**.
3. **Caché y Comportamiento Offline:**
   - El cliente almacena la última política válida descargada y verificada mediante SHA-256 en su almacén local cifrado.
   - Si la política almacenada expira y no hay conectividad con el servidor, el cliente entra en modo seguro restrictivo (*fail-closed*), aplicando únicamente las restricciones de P0.

### Diagnóstico de Política Efectiva:
Desde la Consola Web (pestaña **Estrategias e Identidad > Diagnóstico**) o vía API:
```bash
curl -H "Authorization: Bearer <TOKEN>" \
  https://cercano.local:21114/api/policies/effective?device_id=dev-001
```
La respuesta detalla el valor efectivo final, la regla de resolución aplicada y la fuente ganadora.

---

## 3. Federación de Identidad (SSO)

Cercano admite inicio de sesión federado mediante OpenID Connect (OIDC) y LDAP sobre TLS.

### 3.1 OpenID Connect (OIDC con PKCE)
- **Flujo Obligatorio:** Authorization Code Flow con PKCE (S256).
- **Parámetros Validados:** `issuer`, `audience`, `state` (un solo uso, TTL 10 min), `nonce`, firma JWKS rotativa.
- **Protección contra CSRF y Secuestro:**
  - Prohibida la vinculación automática por coincidencia de correo electrónico (`email`).
  - La vinculación de cuenta federada requiere inicio de sesión local explícito previo.
- **Segundo Factor:** Si el token OIDC no contiene la claim de autenticación multifactor configurada (`mfa_claim`), Cercano exige obligatoriamente su segundo factor TOTP antes de emitir sesión.

### 3.2 Directorio LDAP / Active Directory
- **Cifrado Obligatorio:** Conexión estricta sobre TLS (`ldaps://` puerto 636 o `start_tls: true`). Toda conexión en texto claro (`ldap://`) es rechazada por diseño.
- **Mapeo Explícito:** Únicamente se asignan roles y grupos a usuarios que pertenezcan a grupos explícitamente listados en `group_allowlist`. Grupos desconocidos deniegan el acceso.
- **Protección contra Enumeración:** Credenciales erróneas o cuentas inexistentes devuelven idéntico código HTTP 401 y mensaje genérico.
- **Doble Factor:** Toda autenticación LDAP exitosa requiere validar el código TOTP 2FA de Cercano antes de otorgar privilegios.

---

## 4. Procedimiento de Recuperación de Emergencia (Break-Glass)

Si el proveedor OIDC o el servidor de directorio LDAP/AD sufren una caída, latencia extrema o desconfiguración, los administradores cuentan con un procedimiento de acceso de emergencia local independiente.

### 4.1 Principio de Continuidad Operativa
- El endpoint local de autenticación `/api/auth/login` **no depende de ningún servicio externo**.
- La cuenta de administrador local de emergencia se autentica mediante hash Argon2id almacenado localmente en la base de datos de Cercano.

### 4.2 Pasos para Acceso de Emergencia
1. Acceder a la interfaz de administración:
   ```
   https://<cercano-host>:3000
   ```
2. En la pantalla de inicio de sesión, seleccionar **Acceso Local / Break-Glass**.
3. Ingresar las credenciales locales de la cuenta administrativa de rescate.
4. Introducir el código TOTP 2FA configurado para dicha cuenta.
5. Una vez dentro de la consola:
   - Dirigirse a **Estrategias e Identidad > Proveedores SSO**.
   - Desactivar temporalmente el IdP degradado (`enabled: false`) para evitar bloqueos en cola de usuarios.
   - Revisar los registros en la pestaña **Auditoría** para confirmar eventos de error o intentos de acceso.

### 4.3 Desvinculación de Identidades y Revocación de Sesiones
Si una cuenta federada es comprometida en el proveedor externo:
1. Desde la API o Consola:
   ```bash
   curl -X DELETE -H "Authorization: Bearer <ADMIN_TOKEN>" \
     https://cercano.local:21114/api/identity/links/<LINK_ID>
   ```
2. La desvinculación invalida inmediatamente todas las sesiones activas asociadas a la cuenta federada en la tabla `sessions`, auditando la acción como `identity.unlink`.

---

## 5. Auditoría y Registro Forense

Todas las operaciones de identidad quedan registradas en la cadena criptográfica inmutable `audit_events`:
- `group.create`, `group.delete`, `group.member_add`, `group.member_remove`
- `address_book.create`, `address_book.delete`, `address_book.update`
- `policy.create`, `policy.activate`, `policy.revoke`
- `idp.create`, `idp.update`, `idp.delete`
- `auth.oidc_login`, `auth.ldap_login`, `authz.denied`

**Garantía Cero Secretos:** Las contraseñas de enlace LDAP, secretos de cliente OIDC, hashes o tokens de sesión jamás se persisten en texto claro ni se emiten en los detalles de auditoría o respuestas de la API.
