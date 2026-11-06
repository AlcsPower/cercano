# Auditoría de diseño de la consola web — hallazgos y plan de corrección

**Fecha:** 2026-11-06
**Alcance:** `console-web/` (Vite + React 19 + Tailwind 3 + lucide-react)
**Método:** app real en `http://localhost:3000`, sesión `admin`, API real en `:21114`; capturas y estilos computados con Edge headless (CDP) en 1440×900 y 390×844, temas claro y oscuro.
**Estado del repo:** no se modificó código. Este documento es el único cambio.

> Los defectos funcionales (credenciales hardcodeadas, métricas inventadas, heartbeat sin auth, rotación de claves) están en el informe de auditoría pre-beta y **no** forman parte de este plan. Este plan es solo de interfaz: no cambia comportamiento.

---

## 1. Causa raíz

Los “artefactos mal cargados” no son un problema de diseño, son tres errores de infraestructura de estilos:

1. **Utilidades que no existen en Tailwind** y que no fallan el build: `border-3`, `py-0.2`, `border-black/8`, `bg-black/8`, `border-white/12` (22 usos). Compilan a nada o al valor por defecto.
2. **Colisión de nombres de tokens**: `colors.apple.card` y `boxShadow.apple-card` generan la misma clase `shadow-apple-card`. Gana el color y la sombra sale **blanca** (`rgba(255,255,255,0.78)`), visible como halo en oscuro.
3. **Movimiento a medio hacer**: la hoja modal no tiene salida, el scrim tiene una transición muerta y la tarjeta de login repite su entrada tras cada fallo.

Y dos defectos de plataforma: una fuente remota en un producto LAN/aislado y el tema oscuro aplicado después del primer pintado.

---

## 2. Hallazgos y plan de corrección

Severidad: **A** = se ve roto ahora · **B** = molesta o accesibilidad · **C** = pulido.
Esfuerzo: H = horas.

### Fase A — Tokens y utilidades (hacer primero)

| ID | Sev | Dónde | Cambio exacto | Verificación | Esf. |
|---|---|---|---|---|---|
| **D-01** | A | `tailwind.config.js:41-42` | Borrar `card: 'rgba(255,255,255,0.78)'` y `'card-dark'` de `colors.apple` (no se usan en ninguna clase). Alternativa: renombrar la sombra a `apple-card-shadow`. | `getComputedStyle(nav).boxShadow` del TabBar ya no contiene `rgba(255,255,255,0.78)`. | 0.1 h |
| **D-02** | A | `App.tsx:56` | `border-3` → `border-[3px]` (o `border-4`). | El spinner mide `borderTopWidth: 3px` y se ve el anillo en la pantalla de carga. | 0.1 h |
| **D-03** | A | 22 sitios (ver grep) | `border-black/8` → `border-black/10`; `hover:bg-black/8` → `hover:bg-black/10`; `border-white/12` → `border-white/10`; si se quiere el valor exacto: `border-black/[0.08]`. | `grep -nE 'black/8\|white/12' src` vacío; el build contiene todas las clases. | 1 h |
| **D-04** | A | `TabBar.tsx:71` | `py-0.2` → `py-0.5`. | El badge del contador tiene padding vertical. | 0.1 h |
| **D-05** | C | CI | Añadir un chequeo barato que falle si reaparecen `border-3`, `py-0.2`, `/8`, `/12` en `src/**`. Opcional. | El script falla con una clase inválida de prueba. | 0.5 h |

Sitios de D-03 (ya localizados):

```
App.tsx 56 (border-3) · AppleButton.tsx 36 · Navbar.tsx 70 · TabBar.tsx 53,71
DashboardView.tsx 260,278,296
DevicesView.tsx 190,222,246
LoginView.tsx 108,124
NetworkView.tsx 156
SecurityView.tsx 158
BuilderView.tsx 240,252,351,383,394,408,580
```

### Fase B — Fuente y primer pintado

| ID | Sev | Dónde | Cambio exacto | Verificación | Esf. |
|---|---|---|---|---|---|
| **D-06** | A | `index.html:12-15`, `index.css` | Self-host Manrope: descargar los dos `woff2` (latin y latin-ext, variable 400–800) a `console-web/public/fonts/`, declarar `@font-face` con `font-display: swap` y quitar los `<link>` a `fonts.googleapis.com` / `fonts.gstatic.com`. Si no se quieren añadir binarios: quitar `Manrope` del stack y usar `system-ui` (Segoe UI en Windows). | Con red bloqueada, `document.fonts` contiene Manrope y la UI no cambia de tipografía. | 1 h |
| **D-07** | B | `index.html:6` | Quitar `maximum-scale=1.0, user-scalable=no`. Dejar `viewport-fit=cover`. | Se puede hacer pinch-zoom en móvil. | 0.1 h |
| **D-08** | A | `index.html` + `App.tsx:20-40` | Script inline **antes** del CSS: leer `cercano_theme` (o `prefers-color-scheme`) y añadir `dark` a `<html>`. En `App`, inicializar el estado leyendo `document.documentElement.classList.contains('dark')`. | Recargar en oscuro: a 100 ms el `<html>` ya tiene `dark` y el fondo es oscuro. | 0.5 h |
| **D-09** | C | `App.tsx` | Al cambiar tema, actualizar `<meta name="theme-color">` para que la barra del navegador acompañe. | El color de barra cambia con el toggle. | 0.3 h |

### Fase C — Hoja modal (el defecto estructural)

El `fixed inset-0` está dentro de la vista, que tiene `animate-fade-in` con `transform`. Eso crea un *containing block*: el scrim mide **1216×581 en (172,112)** en vez de 1440×900. Consecuencia: navbar, tab bar y footer no se oscurecen.

| ID | Sev | Dónde | Cambio exacto | Verificación | Esf. |
|---|---|---|---|---|---|
| **D-10** | A | `AppleSheet.tsx:46-94` | Renderizar con `createPortal(..., document.body)`. Además, cambiar los wrappers de vista (`DashboardView:58`, `DevicesView:145`, `SecurityView:87`, `NetworkView:54`, `BuilderView:170`, `LoginView:89`) para animar **solo `opacity`** (o quitar `forwards`/transform tras la entrada). | `overlay.getBoundingClientRect()` = `0,0,innerWidth,innerHeight` en 1440×900 y 390×844; header y footer oscurecidos. | 1.5 h |
| **D-11** | A | `AppleSheet.tsx:44` | Animación de salida: mantener montado 200 ms con un estado `closing`; scrim `opacity 300ms→200ms`; hoja `translateY(16px) scale(.98)`. Usar transiciones con `data-state`, no keyframes (interrumpible). | Cerrar con clic, X y Escape muestra fade de salida, sin corte. | 2 h |
| **D-12** | B | `AppleSheet.tsx:24-42,79-85` | Focus: enfocar el botón de cierre al abrir, devolver el foco al disparador al cerrar, `aria-labelledby` con `id` en el `<h2>`, y compensar el scrollbar (`body.paddingRight = scrollbarWidth`). | Tab queda dentro del diálogo; al cerrar, el foco vuelve al botón “Rotar…”; la página no salta. | 1.5 h |
| **D-13** | B | `AppleSheet.tsx:50` | Quitar `transition-opacity duration-300` (nunca se dispara) y mover la animación al estado de apertura/cierre. | — | 0.2 h |
| **D-14** | C | `AppleSheet.tsx:59` | `transform-origin: center` explícito (los modales son la excepción a los popovers). | — | 0.1 h |

### Fase D — Movimiento

| ID | Sev | Dónde | Cambio exacto | Verificación | Esf. |
|---|---|---|---|---|---|
| **D-15** | B | `LoginView.tsx:59-60` | Quitar `animate-pulse-subtle` de los dos blobs (dejarlos estáticos) o eliminarlos. | Sin animación continua en el login; el perfil de frames en reposo es plano. | 0.2 h |
| **D-16** | B | `LoginView.tsx:64-66` | Mantener `animate-scale-spring` en la clase y añadir `animate-shake` solo mientras dura el shake, sin quitar la base. | Tras 3 fallos, la tarjeta tiembla y **no** vuelve a entrar. | 0.3 h |
| **D-17** | C | `Navbar.tsx:87` | `origin-top-right` en el popover de usuario. | Escala desde el avatar. | 0.1 h |
| **D-18** | B | `StatusPill.tsx:17,50` | `pulse = false` por defecto; dejar el pulso solo en el indicador global del navbar. | Con 2 dispositivos, no hay `pulse-emerald` en las filas. | 0.2 h |
| **D-19** | C | `AppleCard.tsx:22-24` | `transition-all` → `transition-[box-shadow,border-color,transform] duration-150`; hover con `-translate-y-0.5` en vez de `hover:shadow-lg` solo. | Hover sin animar propiedades de layout; sin `transition-all`. | 0.3 h |
| **D-20** | B | `index.css:103-113` | En reduced-motion conservar opacidad/color y el spinner: excepción `.animate-spin { animation-duration: 1s !important; animation-iteration-count: infinite !important; }` después del bloque global. | Con “reducir movimiento” activo, la pantalla de carga sigue girando. | 0.3 h |
| **D-21** | C | `index.css:38` | Quitar `will-change: transform` de `.btn-apple` (o aplicarlo solo en `:hover`). | Sin capas de compositor permanentes por botón. | 0.1 h |

### Fase E — Accesibilidad, layout y copy

| ID | Sev | Dónde | Cambio exacto | Verificación | Esf. |
|---|---|---|---|---|---|
| **D-22** | B | `AppleCard.tsx:20-24` | Si hay `onClick`: `role="button"`, `tabIndex={0}`, `onKeyDown` Enter/Espacio, `focus-visible` visible. | Las tarjetas de dispositivo se abren con teclado. | 0.5 h |
| **D-23** | B | `DevicesView.tsx:320`, `LoginView.tsx:163`, `DashboardView.tsx:110,184` | `text-[11px] text-gray-400` → `text-cercano-slate dark:text-gray-400`; `text-emerald-600` 12 px → `text-emerald-700`. | Contraste ≥ 4.5:1 en los textos pequeños (`gray-400` sobre `#F5F5F7` da 2.36:1). | 0.5 h |
| **D-24** | B | `index.css:20` | Quitar `user-select: none` del `body`; mantenerlo en `.btn-apple`, `button`, `nav`. | Se puede seleccionar y copiar un ID, hostname, IP o mensaje de error. | 0.2 h |
| **D-25** | A | `TabBar.tsx:50-71` | En `< md`: solo iconos (`hidden md:inline` en la etiqueta), `aria-label={tab.label}`, `aria-current={isActive ? 'page' : undefined}`, `transition-colors` en vez de `transition-all`. | A 390 px no hay scroll horizontal: `scrollWidth <= clientWidth`. | 1 h |
| **D-26** | C | `App.tsx:19` | Envolver `setActiveTab` para hacer `window.scrollTo({ top: 0 })`. | Cambiar de vista desde el final de Personalizador aterriza arriba. | 0.2 h |
| **D-27** | B | `NetworkView.tsx:197`, `StatusPill.tsx:23-31`, `DashboardView.tsx:139`, `NetworkView.tsx`/`DashboardView` | `UDP 21115` → `UDP 21116`; “En Línea” para servicios → “Operativo/Detenido”; “Cifrado E2E Ed25519” → “Firma Ed25519”; unificar español (“Puerto”, “Descubrimiento de NAT”, “Señalización”). | La guía de firewall coincide con la tabla de puertos de la misma pantalla. | 0.5 h |
| **D-28** | C | `DashboardView.tsx:91` | KPIs a 2 columnas bajo `sm` y `p-4` (compacto). | En 390 px los 4 KPIs caben sin dos pantallas de scroll. | 0.5 h |
| **D-29** | C | `DevicesView.tsx:97`, `NetworkView.tsx:235,261,287,313` | Reemplazar `window.confirm` y `alert()` por la hoja de confirmación y un toast del sistema de diseño. | No aparecen diálogos nativos. | 3 h |

---

## 3. Orden y dependencias

1. **A** (D-01…D-04): sin esto, el resto se ve distinto a lo diseñado. ~1,5 h.
2. **B** (D-06…D-08): fuente y primer pintado. ~1,5 h.
3. **C** (D-10…D-14): el modal. Es el cambio más grande y el más visible. ~5 h.
4. **D** (D-15…D-21): movimiento. ~1,5 h.
5. **E** (D-22…D-28): accesibilidad y copy. ~3,5 h. D-29 es opcional y puede ir a otra entrega.

Total estimado: **~1,5 días** de una persona. A y E-25 se pueden paralelizar; C depende de A (la hoja usa `shadow` y opacidades).

## 4. Criterios de aceptación

Marcar solo con evidencia:

- [ ] `npm run build` pasa sin warnings nuevos.
- [ ] `grep -nE 'border-3|py-0\.2|black/8|white/12' console-web/src` no devuelve nada.
- [ ] `getComputedStyle(tabBar).boxShadow` no contiene blanco.
- [ ] `document.querySelector('[role="dialog"]').parentElement.getBoundingClientRect()` = `{0,0,innerWidth,innerHeight}` con el modal abierto, en escritorio y móvil.
- [ ] El scrim cubre navbar y footer (captura).
- [ ] Con red bloqueada, la tipografía no cambia y `document.fonts` incluye Manrope (o el stack ya no la pide).
- [ ] Recarga en oscuro: sin flash blanco (captura a 100 ms).
- [ ] Cerrar la hoja con X, Escape y clic en el fondo muestra fade de salida.
- [ ] A 390 px, la barra de pestañas no scrollea horizontalmente.
- [ ] Con reduced-motion, el spinner de carga sigue animando.
- [ ] Matriz de capturas: 1440×900 y 390×844 × claro/oscuro × Panel, Dispositivos, Seguridad (con modal), Red, Personalizador.

## 5. No tocar en este plan

- Credenciales hardcodeadas y modo demo de `client.ts` (informe pre-beta, hallazgo 1).
- Métricas inventadas del dashboard (hallazgo 4).
- Autenticación del heartbeat y bloqueo de login (hallazgos 2 y 3).
- Rotación de claves y TLS (hallazgos 5 y 6).

Esos arreglos cambian lo que la UI muestra; hacerlos después de este plan evita rehacer pantallas.

## 6. Riesgos

- **Renombrar tokens** (`D-01`) toca `tailwind.config.js`: revisar que ninguna clase `bg-apple-card` dependa de ellos (hoy no se usa).
- **Portal del modal** (`D-10`): si se anima la vista con `transform`, volverá el bug aunque haya portal; el fix real es no dejar `transform` en el contenedor o usar portal y quitar `forwards`.
- **Self-hosting de fuente** (`D-06`): añade binarios al repo; verificar que queden bajo la licencia OFL y fuera de `vendor/`.
- **Tailwind JIT en dev** tolera clases inválidas en silencio: por eso conviene el chequeo de D-05.

---

**Evidencia de la auditoría:** capturas y medidas en `%TEMP%\cercano-shot\out` (probe `probes2.json`/`probes3.json`) del equipo del auditor. No se versionan.
