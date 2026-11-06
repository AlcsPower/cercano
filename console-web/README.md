# Cercano — Consola Web de Administración

Portal web oficial de administración y supervisión de infraestructura de **Cercano**, diseñado con fidelidad a las directrices de interfaz fluida de Apple (**Apple Design / WWDC**).

## 1. Principios de Diseño Implementados

- **Apple Fluid Interfaces (WWDC 2018/2026):**
  - **Respuesta instantánea (0 latencia de input):** Toda interacción táctil o de puntero responde en `pointerdown` mediante `active:scale-[0.965]` sin retrasos artificiales.
  - **Física de resortes (Springs):** Transiciones amortiguadas (`damping 1.0`, `response 0.35s`) en hojas modales, popovers e indicadores de estado.
  - **Translucidez y Jerarquía de Materiales:** Superficies flotantes de cristal esmerilado (`backdrop-filter: blur(20px) saturate(180%)`) con borde superior luminoso (`rgba(255, 255, 255, 0.4)`).
  - **Tipografía San Francisco / Manrope:** Espaciado óptico calibrado (`tracking-apple-display`, `-0.025em` para encabezados), contraste accesible y compatibilidad total con el tema claro/oscuro.
  - **Accesibilidad integral:** Soporte estricto de `prefers-reduced-motion` y `prefers-reduced-transparency`.

## 2. Vistas del Portal

1. **Autenticación (macOS Lock Screen / Apple ID):**
   - Tarjeta flotante con efecto de cristal esmerilado, avatar con anillo de marca y animación de agitación (*shake*) ante credenciales incorrectas.
   - Autenticación segura contra `cercano-api` (`POST /api/auth/login`) con emisión de Bearer token y bloqueo temporal tras intentos fallidos.
2. **Panel General (Dashboard):**
   - Métricas de disponibilidad (*uptime*), uso de CPU/Memoria, sesiones remotas activas cifradas y relación de dispositivos conectados vs. registrados.
   - Estado de los 4 procesos clave (`cercano-api`, `cercano-nat`, `hbbs`, `hbbr`).
3. **Directorio de Dispositivos:**
   - Búsqueda instantánea en tiempo real sin retraso de *debounce*.
   - Filtrado por sistema operativo (Windows, Linux, macOS, Android) y por estado (En Línea con punto verde pulsante / Desconectados).
   - Detalle del dispositivo en una **Apple Sheet** modal interactiva (hostname, IP de red, versión de cliente, último heartbeat, copia de ID y eliminación).
4. **Gestión de Claves y Seguridad:**
   - Visualización y copia de la clave pública **Ed25519** del servidor.
   - Cálculo automático de huella digital **SHA-256** mediante Web Crypto API.
   - Modal de rotación de claves (`POST /api/server/keys/rotate`) con advertencia de impacto y respaldo con sello de tiempo.
5. **Servidor y Red:**
   - Matriz de puertos (21114 REST API, 21115 NAT, 21116 Rendezvous, 21117 Relay) y reglas de cortafuegos LAN.
   - Generador y selector de cadena de conexión LAN para clientes (`host:port,key=...`).
   - Centro de descargas de instaladores preconfigurados (.exe, .deb, .dmg, .apk).

## 3. Integración con el Backend (`cercano-api`)

- **Detección automática de conectividad:** La consola verifica el endpoint `/healthz` y las rutas `/api/*` en el puerto `21114`.
- **Modo Demostración / Simulación:** Activado exclusivamente si la variable `VITE_DEMO_MODE=true` está presente en el entorno; en producción o por defecto, la autenticación se realiza de forma estricta contra `cercano-api` sin fallbacks silenciosos.

## 4. Comandos de Ejecución

```bash
# Instalar dependencias
cd console-web
npm install

# Iniciar servidor de desarrollo (puerto 3000 con proxy a :21114)
npm run dev

# Compilar para producción
npm run build

# Previsualizar build de producción
npm run preview
```

## 5. Licencia

Copyright (C) 2026 Cercano Contributors. Distribuido bajo la licencia **GNU Affero General Public License v3.0 (AGPL-3.0-only)**.
