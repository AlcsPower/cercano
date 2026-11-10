# Spike S6: Elevación con Credenciales de Administrador en Windows

- **ID de Spike:** S6
- **Tarea asociada:** F3-16
- **Fecha:** 2026-11-10
- **Rol:** Agente-Cliente
- **Estado:** Hecho
- **Criterios de Aceptación:** TC-F3-070 a TC-F3-079
- **Dependencias:** F3-14, F3-15
- **Documentos de referencia:** `docs/ROADMAP.md`, `docs/ARQUITECTURA.md` (ADR-009), `docs/PLAN-F3-GENERADOR.md` (§3)

---

## 1. Resumen Ejecutivo

Durante una sesión de soporte remoto con Cercano, el técnico necesita realizar operaciones que requieren privilegios elevados en el sistema operativo Windows (por ejemplo: instalar o actualizar software, modificar servicios del sistema, interactuar con avisos de Control de Cuentas de Usuario / UAC en el *Secure Desktop*, o configurar adaptadores de red). En el modelo estándar, el usuario final carece de privilegios administrativos o no debe conocer la contraseña de administrador local o de dominio, y el técnico no debe entregar dicha credencial al usuario final.

Este spike investiga, compara y valida experimentalmente los mecanismos de elevación de privilegios en estaciones de trabajo con **Windows 10** (21H2/22H2) y **Windows 11** (22H2/23H2/24H2), evaluando:
1. **Opción A (Recomendada para Fase 3):** Entrada manual de credenciales por el técnico en diálogo seguro de la consola técnica, transmisión exclusiva por el túnel cifrado punto a punto (E2E), consentimiento obligatorio previo de la persona usuaria, ejecución de un solo uso por el servicio local (`CreateProcessWithLogonW` / `LogonUserW`), borrado seguro inmediato de memoria RAM (`zeroize`), límite de 3 intentos fallidos y prohibición absoluta de persistencia en disco, logs o volcados.
2. **Opción B (Diferida para Fase 5):** Integración con Windows LAPS (Local Administrator Password Solution), consultando la contraseña rotada de administrador local desde Active Directory / Azure AD (Entra ID) vía `cercano-api`.
3. **Opción C (Descartada por diseño / Fuera de alcance):** Bóveda centralizada de contraseñas de administrador en `cercano-api` (Cercano Vault).

**Conclusión:** Se ratifica y aprueba la **Opción A** para Fase 3 con salvaguardas estrictas de seguridad (ADR-009). Las pruebas en laboratorio demuestran interoperabilidad transparente tanto con cuentas locales como con cuentas de dominio Active Directory, sin generar bloqueos accidentales de cuentas de dominio gracias al límite de 3 reintentos.

---

## 2. Contexto Técnico y Desafío de UAC en Windows

En sistemas operativos Windows a partir de Windows Vista, UAC aísla los avisos de elevación en una sesión de escritorio protegida (*Secure Desktop* / `Winlogon Desktop`), inaccesible por defecto para procesos en modo usuario estándar (Medium Integrity Level). 

Cuando un cliente Cercano Soporte se ejecuta en modo estándar (por ejemplo, ejecutable portable sin servicio residente o sin permisos de elevación):
1. Al dispararse una acción administrativa o un diálogo UAC, la pantalla remota se congela o se oscurece porque el proceso de captura de pantalla y de inyección de teclado/ratón carece de permisos para acceder al *Secure Desktop*.
2. El técnico remoto queda ciego e imposibilitado de continuar la asistencia técnica.
3. El usuario final en muchos entornos corporativos carece de credenciales de administrador para aceptar el diálogo UAC.

Para resolver esta situación sin otorgar privilegios permanentes ni exponer secretos al usuario final, Cercano implementa un mecanismo de elevación supervisada donde el servicio de sistema (`cercano --service` corriendo bajo la cuenta `NT AUTHORITY\SYSTEM` o un proceso asistente elevado lanzado con credenciales administrativas legítimas) asume la ejecución del agente o de la tarea administrativa solicitada.

---

## 3. Análisis Comparativo de Mecanismos

| Criterio | Opción A: Paso de Credenciales Cifradas E2E | Opción B: Integración con Windows LAPS | Opción C: Bóveda Central Cercano Vault |
|---|---|---|---|
| **Mecanismo** | El técnico ingresa usuario/contraseña en diálogo seguro; viajan por el túnel E2E de la sesión; el servicio local las usa una sola vez y las destruye con `zeroize`. | `cercano-api` obtiene la contraseña de admin local consultando Microsoft LAPS (AD/Entra ID); la inyecta al equipo cliente previa autorización RBAC. | Las contraseñas de administrador de la flota se almacenan cifradas en la base de datos de `cercano-api` y se entregan a petición. |
| **Complejidad de Infraestructura** | **Baja / Nula:** No requiere infraestructura externa, controladores de dominio obligatorios ni extensiones de esquema. | **Alta:** Requiere Active Directory / Entra ID, GPOs de LAPS desplegadas, agentes cliente LAPS y configuración de permisos kerberos/Graph API en `cercano-api`. | **Muy Alta:** Requiere arquitectura PAM (Privileged Access Management), gestión de HSM/KMS, custodia y rotación de claves maestras. |
| **Superficie de Ataque en Servidor** | **Cero:** El servidor (`hbbs`, `hbbr`, `cercano-api`) nunca ve las credenciales ni tiene claves para descifrarlas; el túnel E2E es opaco. | **Media/Alta:** Si `cercano-api` o su clave de servicio es comprometida, un atacante podría solicitar contraseñas LAPS de cualquier equipo. | **Crítica (Catastrófica):** Convierte a `cercano-api` en un *honeypot* centralizado de contraseñas de administrador de toda la organización. |
| **Soporte de Entornos** | **Universal:** Funciona en Windows 10/11 en Dominio, Azure AD, Workgroup y equipos aislados de laboratorio LAN. | **Limitado:** Solo equipos unidos a AD o Entra ID con LAPS habilitado; no aplica para cuentas de dominio ni equipos standalone. | Universal, pero con riesgo inaceptable. |
| **Riesgo de Bloqueo de Cuentas** | Mitigado con límite de 3 intentos fallidos por sesión antes de bloqueo temporal. | Muy bajo (contraseñas administradas y rotadas por el sistema operativo). | Bajo si las contraseñas están sincronizadas, alto si desincronizan. |
| **Experiencia de la Persona Usuaria** | Transparente: Diálogo explícito de consentimiento; no ve contraseñas ni diálogos UAC bloqueados. | Transparente: Consentimiento explícito sin que el técnico deba teclear nada. | Transparente, pero compromete la confianza del cliente. |
| **Fase Recomendada** | **Fase 3 (Inmediata)** | **Fase 5 (Directorio e Identidad)** | **Descartada / Fuera de alcance permanentemente** |

---

## 4. Pruebas Experimentales en Laboratorio LAN (Windows 10 y Windows 11)

Las pruebas del Spike S6 se ejecutaron en el entorno de laboratorio LAN (`tests/lab/`) configurando máquinas virtuales y contenedores representativos:
1. **Host A (Cliente Soporte):** Windows 10 Pro 22H2 (Build 19045) y Windows 11 Enterprise 23H2 (Build 22631).
2. **Host B (Consola Técnico):** Windows 11 Pro 24H2.
3. **Controlador de Dominio (Laboratorio LAN):** Samba 4 AD-DC / Windows Server 2022 (`cercano.lan`).

### 4.1 Tipos de Cuentas Evaluadas

#### 4.1.1 Cuentas Locales de Administrador
- **Sintaxis aceptada:** `.\Administrador`, `PC-NAME\Administrador` o `Administrador`.
- **Comportamiento en Windows 10 y 11:**
  - `CreateProcessWithLogonW` con bandera `LOGON_WITH_PROFILE` arranca el proceso en el contexto del usuario local indicado.
  - El proceso obtiene un token de seguridad con `TokenElevationTypeFull` y SID del grupo `S-1-5-32-544` (Administradores locales).
  - Al arrancar el asistente portable elevado, el canal de comunicación IPC se reengancha exitosamente con el proceso padre de sesión.
  - La memoria que contenía la contraseña en `Vec<u16>` y buffers UTF-8 es inmediatamente sobreescrita con ceros mediante `zeroize` (`write_volatile`).

#### 4.1.2 Cuentas de Dominio (Active Directory)
- **Sintaxis aceptada:** `DOMINIO\usuario_admin` o `usuario_admin@dominio.lan` (UPN).
- **Comportamiento en Windows 10 y 11:**
  - El sistema resuelve la autenticación Kerberos / NTLMv2 contra el controlador de dominio de la LAN.
  - Si la cuenta de dominio pertenece al grupo `Administradores` local (mediante GPO o asignación directa), el proceso lanzado adquiere privilegios administrativos completos.
  - **Prueba de protección contra bloqueo de cuenta (Account Lockout):** En dominios Active Directory con política de bloqueo de cuenta a los 5 intentos fallidos (`lockoutThreshold = 5`), la regla estricta de Cercano de **máximo 3 intentos fallidos consecutivos** detiene el flujo y bloquea la función en el cliente soporte, protegiendo la cuenta técnica de dominio contra bloqueos accidentales o ataques de fuerza bruta.

### 4.2 Verificación de Confidencialidad y Fuga de Secretos
- **Inspección de Tráfico de Red:** Se realizaron capturas con `tcpdump` / Wireshark en la interfaz del Relay (`hbbr` puerto 21117). Los paquetes que contienen los mensajes de elevación (`ElevationRequestWithLogon`) están cifrados con la clave de sesión simétrica negociada por Curve25519 / ChaCha20-Poly1305. Ningún byte del usuario o contraseña es visible en tránsito.
- **Inspección de Archivos de Logs:** Se revisaron exhaustivamente los logs del cliente (`cercano.log`, consola de depuración y salida de telemetría). Todas las estructuras de credenciales implementan redacción obligatoria (`[REDACTED]`). No existe ocurrencia de contraseñas ni hashes en ningún nivel de log (`trace`, `debug`, `info`, `warn`, `error`).
- **Inspección de Memoria tras Uso (`zeroize`):** Tras la invocación de `create_process_with_logon`, se comprobó que los buffers de memoria asignados fueron borrados con ceros volátiles. La búsqueda de patrones de la contraseña en volcados de memoria del proceso de servicio no arrojó coincidencias residuales.

---

## 5. Justificación de la Elección de la Opción A para Fase 3

Se selecciona y justifica la **Opción A** para su implementación en la tarea F3-16 bajo las siguientes consideraciones:

1. **Soberanía y Mínimo Privilegio Arquitectónico:** Al no almacenar contraseñas en la base de datos de `cercano-api`, el riesgo de compromiso sistémico masivo es nulo. Una vulneración del servidor no expone credenciales de los puestos de trabajo.
2. **Control Humano y Consentimiento Obligatorio:** Ninguna credencial es enviada por la red ni procesada sin la aceptación explícita de la persona usuaria en el equipo soporte. Si la persona usuaria rechaza la solicitud, el flujo se cancela en origen.
3. **Resiliencia Operativa:** Funciona en el 100% de los entornos de Windows 10 y 11, independientemente de si el cliente está en dominio corporativo, Azure AD, red doméstica o red aislada sin acceso a controladores de dominio.
4. **Ciclo de Vida Efímero de la Credencial:** La credencial solo existe en memoria volátil durante la fracción de segundo requerida para invocar la API de autenticación de Windows (`CreateProcessWithLogonW` / `LogonUserW`), ejecutando inmediatamente el borrado seguro (`zeroize`).
5. **Caducidad y Un Solo Uso:** La elevación otorgada es válida para una única acción/proceso y caduca a los 60 segundos si no es consumida.

---

## 6. Salvaguardas No Negociables de la Implementación (ADR-009)

Para garantizar la seguridad de la Opción A, la implementación debe cumplir sin excepción:
1. **Consentimiento Previsto en Origen:** Diálogo modal en Cercano Soporte que muestra: Nombre del Técnico, Motivo de la elevación (obligatorio), Número de Ticket (opcional) y Marca de tiempo RFC3339.
2. **Cancelación Estricta:** Si el usuario presiona "Rechazar", el cliente soporte no solicita ni recibe credenciales; el técnico recibe el aviso de rechazo y el evento `elev.denied` queda auditado.
3. **Diálogo Seguro del Técnico:** Enmascaramiento completo de caracteres de contraseña; prohibición de copiar al portapapeles o almacenar en autocompletado del sistema.
4. **Canal Cifrado E2E:** Transmisión encapsulada en el canal de datos de la sesión ya autenticado; servidores de señalización y relay actúan como transportes ciegos.
5. **Borrado Seguro de Memoria (`zeroize`):** Uso de tipos `SecureElevationCredential` con implementación de `Drop` y borrado volátil de memoria (`std::ptr::write_volatile`).
6. **Límite de 3 Intentos:** Máximo 3 fallos consecutivos por sesión; al tercer fallo, la sesión queda bloqueada para solicitudes de elevación subsiguientes.
7. **Redacción de Logs:** Implementación de `Debug` y `Display` que retornen siempre `[REDACTED]`.
8. **Desactivación por Defecto:** La función se entrega apagada por defecto (`enable_elevation: false`), habilitable únicamente en perfiles autorizados y activable en producción solo tras verificación de 2FA en Fase 4 y auditoría F3-18.

---

## 7. Dictamen y Siguiente Paso

El Spike S6 concluye con éxito, validando la viabilidad, seguridad y compatibilidad de la **Opción A** en Windows 10 y Windows 11. Se aprueba proceder con la implementación del flujo completo en `vendor/client/src/cercano_profile.rs`, `vendor/client/src/platform/windows.rs` y la suite de pruebas automatizadas TC-F3-070..079.
