# ADR-014 — Diferimiento de la integración con Windows LAPS (F5-10)

- **Estado:** Aprobado (2026-11-16) por Coordinador, Agente-ControlPlane y Agente-Seguridad.
- **Fecha:** 2026-11-16
- **Fase:** F5
- **Decisores:** Dueño del producto, Coordinador, Agente-ControlPlane, Agente-Cliente, Agente-Seguridad
- **Relacionados:** [`docs/specs/identidad.md`](../specs/identidad.md), [`docs/PLAN-F5-IDENTIDAD.md`](../PLAN-F5-IDENTIDAD.md), [`docs/adr/012-identidad-grupos-federacion.md`](012-identidad-grupos-federacion.md), [`docs/specs/audit-events.md`](../specs/audit-events.md)

---

## 1. Contexto

En el marco de la Fase 5 (Identidad y Control de Acceso), se evaluó la integración con **Windows LAPS** (Local Administrator Password Solution) para permitir que los operadores de soporte remoto obtuvieran dinámicamente credenciales de administrador local rotadas para tareas de mantenimiento o soporte desatendido.

El objetivo previsto era evitar contraseñas compartidas o estáticas para elevación administrativa en equipos Windows del parque corporativo.

---

## 2. Análisis de Viabilidad y Riesgos de Seguridad

Una integración segura de LAPS impone requisitos de arquitectura que presentan riesgos desproporcionados para la versión actual:

1. **Riesgo de centralización y bóveda de secretos:** Cercano no es ni debe convertirse en un gestor de secretos corporativos (PAM/Vault). Almacenar o intermediar contraseñas locales en el control plane crea un objetivo de alto valor (*honeypot*).
2. **Exposición de credenciales de directorio:** Para que el backend consulte contraseñas LAPS directamente en Active Directory o Microsoft Entra ID, Cercano necesitaría credenciales de servicio con permisos de lectura sobre atributos confidenciales (`ms-Mcs-AdmPwd` o LAPS v2 en AD), lo cual comprometería todo el dominio si el servidor de Cercano fuera vulnerado.
3. **Flujo de entrega efímera no trivial:** Una entrega segura requeriría técnico con 2FA verificado, sesión activa en el equipo exacto, consentimiento explícito del usuario remoto en pantalla, entrega efímera en memoria volátil sin persistencia en disco ni renderizado en texto claro en logs, y rotación inmediata forzada tras el uso.
4. **Suficiencia de F3-16:** El mecanismo de elevación UAC y ejecución interactiva (`consent` y tecleo local o mediante canal protegido) implementado en la Fase 3 cubre de forma limpia la necesidad operativa sin requerir acceso a las contraseñas LAPS desde Cercano.

---

## 3. Decisión

**Se difiere formalmente la integración con Windows LAPS en Cercano v1.**

Reglas aplicadas:
1. **Sin bóvedas ni tablas de secretos (TC-F5-051):** No se crea ninguna tabla, campo en base de datos ni endpoint de recuperación de contraseñas de administrador.
2. **Sin persistencia ni fugas en auditoría:** Ninguna contraseña de sistema operativo se registra, transmite ni almacena a través de la infraestructura de Cercano.
3. **Mecanismo vigente de elevación:** La elevación de privilegios continúa rigiéndose por las políticas de instalador (P0) y las estrategias centrales (P1..P3) de Cercano, utilizando la solicitud interactiva de elevación con consentimiento del usuario implementada en F3-16.
4. **Criterio de reapertura:** Si en versiones futuras un despliegue requiere LAPS, se evaluará una integración directa en el agente cliente local (mediante APIs locales de Windows LAPS invocadas bajo el contexto de `SYSTEM` local previa autorización criptográfica de Cercano), sin que el backend conozca ni reciba jamás la contraseña.

---

## 4. Consecuencias

### Positivas
- **Máxima reducción de riesgos de seguridad:** Cero riesgo de fuga masiva de contraseñas de administrador local desde el backend o las comunicaciones de red.
- **Simplicidad arquitectónica (Ponytail):** No se introducen dependencias complejas con APIs de Active Directory ni Azure Graph API.
- **Cumplimiento estricto de auditoría:** Se mantiene la política de cero secretos en logs y eventos de auditoría.

### Negativas
- El técnico de soporte debe contar con un mecanismo externo corporativo para consultar la contraseña LAPS si requiere iniciar sesión interactiva como administrador local cuando no hay usuario frente al equipo.
