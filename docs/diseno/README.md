# Diseño objetivo de la aplicación de escritorio

**Fecha:** 2026-11-25 · **Estado:** aprobado por el Dueño del producto como diseño objetivo · **Tarea:** F3-23

[`app-soporte.html`](app-soporte.html) es la especificación visual de **Cercano Soporte**: la ventana principal y el diálogo de consentimiento. Se abre en cualquier navegador. Su imagen está en [`../img/app-escritorio-maqueta.png`](../img/app-escritorio-maqueta.png) y la interfaz actual en [`../img/app-escritorio-real.png`](../img/app-escritorio-real.png).

La implementación no tiene que copiarlo píxel a píxel. Lo que sí debe cumplir:

## Ventana principal (rol `soporte`)

| Zona | Contenido | Hoy (interfaz heredada) |
|---|---|---|
| Cabecera | Logo, nombre y contacto de la organización (marca entregada por el agente, F3.5-10) y estado «Conectado al servidor» | No existe |
| Tarjeta principal | «Tu ID de asistencia» en grande, con el texto «Nadie puede entrar sin tu aprobación» | ID pequeño en la barra lateral |
| Tarjetas secundarias | Código de un solo uso y nombre del equipo con su sistema | Contraseña en la barra lateral |
| Acciones | «Chat de soporte» (con contador de no leídos) y «Ajustes» | Solo «Chat de soporte» |
| Aviso | «Esta aplicación solo **recibe** asistencia…» | No existe |
| Pie | «Powered by Cercano · AGPL-3.0», versión y rol | «Con tecnología de RustDesk» (incumple AGENTS.md §6) |
| **No aparece** | Panel «Controlar escritorio remoto», historial, favoritos, libreta y descubrimiento | Visibles |

## Diálogo de consentimiento

Quién se conecta (nombre del técnico y organización), el ticket si lo hay, y una tabla de permisos (pantalla, teclado y ratón, archivos, grabación) con el valor que fija la política. Botones **Rechazar** y **Aceptar sesión**, de igual tamaño, con Aceptar como acción principal. Debajo se recuerda que la sesión se puede terminar en cualquier momento.

## Chat de soporte (lado de la persona usuaria)

Cuando la conversación está asignada, la cabecera del chat dice **«Atendido por <nombre del técnico>»** y cada mensaje del técnico lleva su nombre. Es el nombre visible que el técnico tiene en la consola, nunca su usuario de inicio de sesión. Contrato en [`docs/specs/chat.md`](../specs/chat.md) §14; tarea F4.5-17.

## Rol `tecnico`

Conserva el panel de conexión, el historial y la libreta, porque los necesita (F3-15), con la misma paleta, tipografía y pie que el rol `soporte`.

## Tokens

Paleta oficial de [`branding/README.md`](../../branding/README.md): Azul Cercano `#3B5BFF`, Verde cursor `#2DD4A7`, Azul noche `#0B1426`, Niebla `#F2F5FB`, Borde `#DCE2EE`, Gris azulado `#4A5878`. Tarjetas con radio de 14 px, botones de 52 px de alto y el ID en fuente monoespaciada.
