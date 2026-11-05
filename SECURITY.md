# Política de seguridad

Cercano es software de acceso remoto: una vulnerabilidad puede dar control sobre equipos ajenos. Tratamos los reportes con prioridad.

## Cómo reportar una vulnerabilidad

**No abras un issue público ni publiques detalles.**

- Usa la opción **Report a vulnerability** de la pestaña *Security* de este repositorio en GitHub (si no aparece, pide a los mantenedores que activen *Private vulnerability reporting*), o
- contacta de forma privada a los mantenedores de `AlcsPower`.

Incluye, si puedes: versión o commit, componente afectado (cliente, servidor, `cercano-api`, generador, consola), pasos para reproducirlo, impacto estimado y, si la tienes, una propuesta de mitigación.

## Qué esperar

Es un proyecto en fase inicial (F0, sin versiones publicadas). Los mantenedores confirmarán la recepción y tratarán el reporte de forma privada hasta tener una corrección. No hay plazos garantizados todavía; se fijarán antes de la primera versión beta (F7).

## Alcance

Dentro de alcance: código propio de Cercano (`control-plane/`, `audit-core/`, `builder/`, `console-web/`, `deploy/`), los parches sobre el código heredado (`patches/`) y los instaladores generados.

Fuera de alcance: vulnerabilidades del código de RustDesk que no dependan de nuestros parches; repórtalas también al proyecto original. Si dudas, repórtalo aquí y lo derivamos.

## Reglas para quien pruebe seguridad

Prueba solo en tu propio laboratorio o contra instancias que controles. No accedas a datos ajenos, no hagas pruebas de denegación de servicio contra sistemas de terceros y no conserves información obtenida durante las pruebas.

## Para los agentes del proyecto

Los hallazgos internos se anotan en `docs/status/SECURITY-PRIVADO.md` y se avisa al Coordinador (ver `AGENTS.md`, sección 7).
