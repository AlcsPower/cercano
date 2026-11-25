# ADR-015 — Agente Cercano por organización y aplicación de escritorio genérica

- **Estado:** Aprobado por el Dueño del producto (2026-11-25), con el alcance recortado a la configuración aparte (§2.3). Pendiente de ratificación del Coordinador y del Agente-Seguridad antes de cerrar F3.5-01.
- **Fecha:** 2026-11-25 (aprobación del Dueño: 2026-11-25)
- **Fase:** F3.5 (ver [`docs/PLAN-F3.5-AGENTE.md`](../PLAN-F3.5-AGENTE.md))
- **Decisores:** Dueño del producto, Coordinador, Agente-Cliente, Agente-Builder, Agente-ControlPlane, Agente-Seguridad
- **Reemplaza en parte:** ADR-005 («compilar una vez, configurar muchas» con perfil firmado **embebido en el cliente**)
- **Mantiene:** ADR-008 (roles `soporte`/`tecnico` en el perfil firmado y aplicados en el servidor), ADR-009 (elevación), ADR-010 (Cercano Chat), ADR-012 (estrategias con el perfil como techo)
- **Relacionados:** [`docs/PLAN-F3-GENERADOR.md`](../PLAN-F3-GENERADOR.md), [`docs/specs/cercano-profile.md`](../specs/cercano-profile.md), [`patches/INDEX.md`](../../patches/INDEX.md)

## 1. Contexto

Cercano quiere ser un producto de uso libre: igual que con el proyecto del que deriva, una persona
descarga la aplicación y la usa con **cualquier** servidor Cercano, propio o en la nube. Hoy no es
posible, porque cada instalador queda atado a un despliegue concreto al compilarlo:

- **Direcciones fijas.** El parche `003-client-default-endpoints.patch` deja ID server, relay y API en
  `127.0.0.1`.
- **Clave de confianza compilada.** El parche `005-client-signed-profile.patch` verifica el perfil
  contra `DEFAULT_PROFILE_PUBLIC_KEY_BASE64` o contra `CERCANO_PROFILE_PUBLIC_KEY`, fijada al compilar.
  Cada organización firma con su propia clave, así que un binario publicado no puede validar el perfil
  de otro servidor.
- **Perfil embebido.** ADR-005 mete el perfil en el instalador del cliente. Cambiar algo (servidor,
  marca, rol) exige generar y redistribuir la aplicación entera, y el binario resultante deja de ser
  el mismo para todos.
- **La lógica del servidor vive en la interfaz.** Identidad del dispositivo, política efectiva
  (parche 012), latido (parche 003) y transporte del chat (parche 008) están dentro del cliente
  Flutter/Rust heredado. Cada cambio toca `vendor/` y agranda la deriva respecto a upstream (R2).

Restricciones que mandan: la firma Authenticode se aplica una sola vez, en la máquina de compilación
Windows (F3-19), y la clave de firma de código **no** se guarda en el servidor de la organización
(AGENTS.md §7); el icono del `.exe`, del `.msi` y de la aplicación es siempre el logo de Cercano
(decisión del dueño del 2026-11-16, F3-22); el rol se aplica en el servidor (ADR-008); y toda función
de acceso remoto debe poder auditarse y desactivarse por política.

## 2. Decisiones

1. **Dos piezas con responsabilidades separadas.**

   | | **Aplicación Cercano** (`cercano.exe`, genérica) | **Agente Cercano** (`cercano-agent.exe`, por organización) |
   |---|---|---|
   | Qué es | Interfaz de escritorio: conexión remota y chat | Servicio de Windows `CercanoAgent` sin interfaz gráfica, como `LocalSystem` |
   | Configuración propia | Ninguna embebida | Perfil firmado de la organización, claves fijadas, credencial del dispositivo |
   | Compilación | Una por versión y plataforma, la misma para todo el mundo | Una por versión y plataforma, la misma para todo el mundo; lo particular va en un archivo o código de configuración aparte (decisión 3) |
   | Habla con el servidor | Solo el flujo de la sesión remota con hbbs/hbbr | `cercano-api`: vinculación, política, revocación, auditoría, latido, chat |
   | Sin la otra pieza | Modo libre (decisión 6) | No sirve de nada |

   El agente es código nuevo en `agent/` (Rust, AGPL-3.0), **fuera de `vendor/`**. No se integra en el
   servicio heredado del cliente, para mantener el diff contra upstream en un solo puente pequeño.

2. **El flujo de la sesión remota no pasa por el agente.** Vídeo, entrada, transferencias y relay
   siguen yendo de la aplicación (y de su servicio heredado) a hbbs/hbbr. El agente solo entrega la
   configuración necesaria para conectarse (hosts y clave pública del servidor). Así no se añaden
   latencia ni un punto de fallo al camino crítico.

3. **El servidor genera una configuración, no un binario.** El paquete de instalación (agente +
   aplicación, `.exe` y `.msi`) se compila y firma una vez en la máquina de compilación (F3-19) y es
   el mismo para todas las organizaciones. Lo particular de cada una es la **configuración de la
   organización**: el perfil firmado (sin logo, para que quepa en una línea de comandos), que
   `cercano-api` entrega de tres formas equivalentes:
   - archivo `cercano-org.json` junto al instalador (el instalador lo lee de su misma carpeta);
   - código de configuración (el mismo perfil en base64url) para
     `cercano-agent enroll --config <código>` o `msiexec /i cercano.msi CERCANO_CONFIG=<código>` en
     GPO/Intune;
   - un `.zip` con el instalador genérico firmado y el `cercano-org.json`.

   Ningún binario se modifica, así que la firma Authenticode no se toca. La integridad de la
   configuración la garantiza la firma Ed25519 del perfil. El servidor no necesita compilador, WiX,
   Windows ni el certificado de firma de código.

   *Diferido:* meter la configuración dentro del instalador firmado («instalador etiquetado») para
   entregar un solo archivo. Se retoma con un spike propio si la experiencia de despliegue lo pide.

4. **La confianza se fija al instalar, no al compilar.** La configuración lleva el perfil firmado con la
   clave de la organización y la propia clave pública de verificación de perfiles. En la primera
   instalación el agente:
   - verifica la firma del perfil contra la clave incluida y su caducidad;
   - **fija** (*pin*) en `%ProgramData%\Cercano\agent\` (ACL: solo `SYSTEM` y `Administradores`) la clave
     de perfiles de la organización, la clave pública del servidor y los hosts.

   A partir de ahí todo perfil o política nueva debe venir firmada por la clave fijada. La clave solo
   cambia reinstalando con derechos de administrador o con un mensaje de rotación firmado por la clave
   anterior. La clave compilada `CERCANO_PROFILE_PUBLIC_KEY` queda solo para pruebas y laboratorio. En
   modo interactivo, el instalador muestra el nombre de la organización, el host del servidor y la
   huella de la clave antes de confirmar.

5. **Vinculación del dispositivo.** Al primer arranque el agente genera su par Ed25519 (protegido con
   DPAPI de máquina) y llama a `POST /api/agent/enroll` con el token de registro del perfil (menor
   privilegio, con caducidad, límite de usos y revocable, F3 §5). El servidor asocia
   `device_id` ↔ `installer_id` ↔ `role` y emite la credencial del dispositivo. Desde entonces el agente
   se autentica con reto y firma (el mismo esquema que el chat, F4.5-03). La revocación (F3-09) y el
   rol (ADR-008) siguen aplicándose en el servidor.

6. **Tres estados de la aplicación.**

   | Estado | Cuándo | Comportamiento |
   |---|---|---|
   | **Gestionado** | Agente instalado, vinculado y accesible | Configuración bloqueada; rol, política efectiva, auditoría, chat y marca de la organización |
   | **Libre** | No hay agente instalado | Como el proyecto de origen: servidor, relay y clave se configuran a mano en Ajustes → Red. Sin chat, sin roles, sin política central. Se muestra «No gestionado» |
   | **Bloqueado** | El agente está instalado (marca en `HKLM\SOFTWARE\Cercano\Agent`) pero no responde, no está vinculado, fue revocado o su política caducó sin red | **Falla cerrado:** no acepta conexiones entrantes nuevas y muestra el diagnóstico. Nunca cae a modo libre, para que detener el servicio no sirva para saltarse la política |

   La aplicación ya no trae direcciones por defecto: sin agente y sin configuración manual, pide un
   servidor.

7. **Canal local agente ↔ aplicación.** *Named pipe* `\\.\pipe\cercano-agent`, protocolo versionado de
   mensajes JSON con prefijo de longitud (contrato en `docs/specs/agente-ipc.md`, F3.5-03). Reglas:
   - El agente crea la tubería con `FILE_FLAG_FIRST_PIPE_INSTANCE` y una DACL que solo permite conectar
     a `SYSTEM` y a usuarios interactivos.
   - El agente verifica al llamante: la imagen del proceso (vía `GetNamedPipeClientProcessId`) está en
     el directorio de instalación y su firma Authenticode es del mismo firmante que el agente.
   - La aplicación verifica al servidor de la tubería: el proceso es el servicio `CercanoAgent`, corre
     como `SYSTEM` y tiene la misma firma. Así se evita la suplantación de la tubería.
   - **La aplicación solo lee configuración.** Puede pedir configuración, marca, rol y política; usar
     el chat; y entregar eventos de auditoría a la cola del agente. No puede cambiar la configuración,
     las claves ni la vinculación.
   - Nunca viajan por la tubería credenciales de elevación (siguen en el canal cifrado de la sesión,
     ADR-009) ni secretos de larga vida del dispositivo.

8. **El agente es el intermediario con `cercano-api`.** Se mudan del cliente al agente:
   - vinculación, identidad y revocación (hoy en el parche 005);
   - descarga, caché y evaluación de la política efectiva con fallo cerrado (parche 012);
   - latido de dispositivo (parche 003);
   - transporte del chat, REST y SSE (parche 008); la interfaz Flutter del chat (parche 009) se queda
     en la aplicación y habla con el agente por la tubería;
   - cola persistente de auditoría con reenvío (*store-and-forward*): los eventos del cliente
     (parche 004) se entregan al agente, que los envía autenticado sobre HTTPS.

   Se quedan en la aplicación: modos soporte y técnico de la interfaz (parche 006, con el rol leído
   del agente), elevación (parche 007) y escalado `cercano://` (parche 010).

9. **La marca se aplica en tiempo de ejecución.** El perfil trae `organization_name`; el logo (PNG
   validado: tipo, dimensiones y tamaño máximo) y el color de acento los descarga el agente de
   `cercano-api` tras vincularse, por HTTPS contra el servidor fijado. La aplicación los recibe del
   agente y los muestra en la ventana y el chat, con «Powered by Cercano»; el instalador interactivo
   muestra el nombre de la organización. No se modifican recursos de
   los binarios. Conforme a la decisión del 2026-11-16, el icono del ejecutable, de la barra de tareas
   y de «Agregar o quitar programas» sigue siendo el logo de Cercano. Esto sustituye el enfoque de
   F3-22 (marca leída del perfil embebido en el cliente).

10. **Diagnóstico por línea de comandos, sin interfaz.** `cercano-agent status`, `test-connection`,
    `policy show`, `logs --tail N`, `enroll`, `re-enroll` y `export-diagnostics`, con `--json` para
    usarlo desde PowerShell (`ConvertFrom-Json`). Lo que cambia estado exige administrador; ninguna
    salida incluye secretos, tokens ni claves privadas.

11. **Generador desde la consola web.** El formulario de F4-07 define los parámetros (rol, servidor,
    marca, política inicial, caducidad, grupo); `cercano-api` firma el perfil y ofrece, en descarga
    autenticada con caducidad, el `cercano-org.json`, el código de configuración y el `.zip` con el
    instalador genérico, mostrando el hash del instalador y la huella de la clave. Se reutilizan el
    servicio de build (F3-07), la auditoría `build.*` (F3-08) y la revocación (F3-09).

12. **Plataformas.** Windows primero (decisión D2). macOS (launchd y socket local con verificación de
    firma) y Linux (systemd y socket Unix con `SO_PEERCRED`) se planifican al cerrar F3.5, con el mismo
    contrato de canal local.

## 3. Consecuencias

**Positivas**

- Un solo binario de aplicación por versión, descargable y usable con cualquier servidor: el objetivo
  de uso libre.
- Cambiar servidor, marca o rol de una organización no exige compilar ni volver a firmar nada; el
  servidor solo firma un JSON, en milisegundos y sin herramientas de Windows.
- Ningún truco sobre la firma de código: los binarios publicados son exactamente los que salen de la
  máquina de compilación.
- El certificado de firma de código no sale de la máquina de compilación.
- La lógica de Cercano sale de `vendor/` hacia `agent/`: menos parches, menos deriva con upstream.
- El diagnóstico en campo se hace con comandos, sin abrir la aplicación ni pedirle nada a la persona
  usuaria.

**Negativas y riesgos**

- **Confianza en el primer uso.** Quien distribuya el instalador genérico con un `cercano-org.json` o
  un código propio consigue que apunte a su servidor (el mismo riesgo que ya tiene el proyecto de
  origen al configurar por nombre de archivo). Se mitiga con la confirmación visible de organización, host y
  huella en la instalación interactiva, la descarga autenticada desde la consola propia y la guía de
  despliegue.
- **Superficie local nueva.** La tubería es una frontera de privilegios (servicio `SYSTEM` ↔ usuario).
  Se mitiga con verificación mutua de firma, DACL, protocolo mínimo de solo lectura y *fuzzing* (F3.5-14).
- **Dos procesos que mantener sincronizados.** Las versiones de agente y aplicación pueden desalinearse.
  Se mitiga con versión de protocolo negociada y empaquetado conjunto.
- **Trabajo rehecho.** Partes de los parches 003, 005, 008 y 012 se mudan al agente, y F3-22 se rehace.
- **Dos piezas que entregar.** Instalador y configuración viajan por separado (o juntos en un `.zip`);
  si el `cercano-org.json` se pierde, el agente queda sin vincular y la aplicación bloqueada hasta
  ejecutar `cercano-agent enroll`.

## 4. Alternativas consideradas

| Alternativa | Por qué se descarta |
|---|---|
| Mantener ADR-005 (perfil embebido en el cliente) | Cada organización recibe un binario distinto; no hay producto descargable de uso libre. |
| Recompilar por organización en el servidor | Exige el toolchain de Windows (Flutter, MSVC, vcpkg) y el certificado de firma en cada servidor; viola AGENTS.md §7 y la decisión de F3-19. |
| Volver a firmar en el servidor tras modificar el binario | Igual que la anterior: la clave de firma de código tendría que vivir en el servidor. |
| Etiquetar el instalador firmado (zona no autenticada del PKCS#7 o `.mst`) | **Diferida**, no descartada: da un solo archivo, pero exige un spike frente a `EnableCertPaddingCheck` y SmartScreen y código de etiquetado propio. La configuración aparte resuelve lo mismo sin ese riesgo. |
| Solo configuración manual, como el proyecto de origen | Sirve para el modo libre, pero no da roles, política, auditoría ni chat gestionados; se conserva como modo libre. |
| Integrar el agente en el servicio heredado del cliente | Más parches en `vendor/` y más deriva; mezcla la lógica de Cercano con la de upstream. |
| Pasar el flujo de la sesión por el agente | Añade latencia y un punto de fallo sin beneficio de seguridad: el protocolo ya cifra de extremo a extremo. |
| Inyectar la marca modificando recursos del ejecutable | Rompe Authenticode, se pierde en cada actualización y contradice la decisión del 2026-11-16 sobre el icono. |
| Caer a modo libre si el agente no responde | Permitiría saltarse la política deteniendo el servicio; se falla cerrado. |

## 5. Referencias

- Plan, tareas y criterios de aceptación: [`docs/PLAN-F3.5-AGENTE.md`](../PLAN-F3.5-AGENTE.md).
- Contrato del canal local (a redactar en F3.5-03): `docs/specs/agente-ipc.md`.
- Perfil firmado: [`docs/specs/cercano-profile.md`](../specs/cercano-profile.md).
- Generador y roles: [`docs/PLAN-F3-GENERADOR.md`](../PLAN-F3-GENERADOR.md), ADR-008 en [`docs/ARQUITECTURA.md`](../ARQUITECTURA.md) §3.
