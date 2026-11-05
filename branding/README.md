# Marca de Cercano — logo y guía de uso

Esta carpeta contiene el logo de Cercano, sus formatos exportados, el código fuente editable del diseño y las reglas para usarlo en el cliente, el servidor, los instaladores y la documentación.

> **Origen:** el diseño se creó en un lienzo de Claude Design («Logo Cercano», hoja *Cercano — logo y marca*). Su fuente editable está en [`source/design-canvas/`](source/design-canvas/). Es un diseño original: no deriva de la marca ni del logo de RustDesk.

## 1. Contenido

| Ruta | Qué es | Cuándo usarlo |
|---|---|---|
| `logo/cercano-icon.svg` | Símbolo (icono de la app) en vectores | Fuente de verdad del símbolo; web, documentación, plantillas |
| `logo/cercano-wordmark-light.svg` | Símbolo + «cercano» para fondos claros | Cabeceras de documentación, README, consola web |
| `logo/cercano-wordmark-dark.svg` | Símbolo + «cercano» para fondos oscuros | Pantallas de inicio oscuras, presentaciones |
| `png/cercano-icon-{16…1024}.png` | Icono en 9 tamaños (16, 24, 32, 48, 64, 128, 256, 512, 1024 px), fondo transparente en las esquinas | Iconos de aplicación, favicon, tiendas, instaladores |
| `png/cercano-icon.ico` | Icono de Windows con 7 tamaños (16 a 256) | Ejecutable y MSI del cliente, accesos directos |
| `source/design-canvas/` | `Main.dc.html` y `canvas.json` del lienzo original | Editar el diseño o reexportar el wordmark |
| `tools/export_icons.py` | Script que regenera los PNG y el `.ico` desde el SVG | Tras cualquier cambio en `cercano-icon.svg` |

## 2. Anatomía y paleta

El símbolo es un cuadrado de esquinas redondeadas (radio 16 sobre 64) con un anillo blanco abierto (una «C») y un cursor verde dentro. El anillo remite a «cercano» y el cursor al control remoto.

| Color | Hex | Rol | Contraste |
|---|---|---|---|
| Azul Cercano | `#3B5BFF` | Fondo del icono, color de marca principal | 5.09:1 con blanco; 3.61:1 sobre `#0B1426` |
| Verde cursor | `#2DD4A7` | Cursor del símbolo, acento | 9.71:1 sobre `#0B1426`; **2.69:1 sobre `#3B5BFF`** |
| Azul noche | `#0B1426` | Texto y fondos oscuros | 18.38:1 sobre blanco |
| Niebla | `#F2F5FB` | Fondos claros de tarjetas | 16.83:1 con `#0B1426` |
| Borde | `#DCE2EE` | Bordes y separadores en la hoja de marca | — |
| Gris azulado | `#4A5878` | Texto secundario y etiquetas | 7.10:1 sobre blanco; 6.50:1 sobre `#F2F5FB` |

Los contrastes se calcularon con la fórmula de luminancia relativa de WCAG 2.x.

**Tipografía:** [Manrope](https://fonts.google.com/specimen/Manrope) (licencia OFL). El wordmark usa Manrope ExtraBold (800), 64 px, con espaciado de letras de −2 px y en minúsculas: «cercano». Los títulos de la hoja de marca usan 700 y 800.

**Lema:** «Soporte remoto, como si estuvieras ahí.»

### Observación de accesibilidad

El cursor verde sobre el fondo azul del icono tiene un contraste de 2.69:1, por debajo del 3:1 que WCAG 2.x pide para elementos gráficos esenciales. El símbolo sigue siendo legible porque el anillo blanco (5.09:1) lleva la identidad, pero el cursor pierde nitidez en tamaños de 16 y 24 px. Si se quiere corregir, las opciones son oscurecer el verde, aclarar el azul o dar al cursor un contorno blanco. Es una decisión de diseño pendiente de la persona responsable de la marca (decisión **D1** del roadmap).

## 3. Reglas de uso

Las reglas de esta sección son una propuesta del equipo de coordinación a partir del diseño; no vienen del lienzo original.

1. **Tamaño mínimo:** 24 px de ancho para el icono en pantalla (el menor tamaño mostrado en la hoja de marca); 16 px solo como favicon o icono de bandeja, usando `png/cercano-icon-16.png` y `.ico`.
2. **Espacio libre:** deja alrededor del icono, como mínimo, un margen del 25 % de su ancho.
3. **Sobre fondo claro u oscuro:** el icono es el mismo en ambos casos; solo cambia el color del texto del wordmark (`#0B1426` sobre claro, `#FFFFFF` sobre oscuro).
4. **No modificar:** no cambiar colores, proporciones, radio de esquina, ni la posición del cursor; no añadir sombras, degradados ni efectos; no girar ni deformar.
5. **No mezclar con otras marcas:** el nombre y el logo de RustDesk no deben aparecer en ningún binario, instalador ni pantalla del producto, salvo la atribución legal exigida por la licencia (ver `NOTICE`).
6. **Un solo símbolo por pantalla:** el icono no se repite como decoración.

## 4. Cómo se usa en el producto

| Dónde | Qué archivo | Tarea del plan |
|---|---|---|
| Icono del cliente de escritorio (Windows) | `png/cercano-icon.ico` | F1-07 (rebranding del cliente) |
| Icono del cliente (Flutter: Linux, Android, iOS) | `png/cercano-icon-512.png` y `-1024.png` como origen | F1-07 |
| Icono de bandeja y notificaciones | `png/cercano-icon-16.png`, `-24.png`, `-32.png` | F1-07 |
| Instalador `.exe`/`.msi` y accesos directos | `png/cercano-icon.ico` | F3-05 |
| Campo «icono» del perfil del generador de instaladores | `png/cercano-icon.ico` por defecto; los clientes pueden reemplazarlo | F3-01 |
| Consola web (favicon y cabecera) | `logo/cercano-icon.svg` y `logo/cercano-wordmark-*.svg` | F4 |
| README y documentación | `logo/cercano-wordmark-light.svg` | continuo |

Aviso para el generador (F3): los perfiles personalizados pueden cambiar el icono y el nombre visibles, pero el «acerca de» del cliente debe conservar siempre la atribución AGPL y de origen.

## 5. Mantenimiento

### Regenerar los PNG y el `.ico`

Desde la raíz del repo:

```bash
pip install playwright pillow
playwright install chromium
python3 branding/tools/export_icons.py
```

El script lee `logo/cercano-icon.svg` y escribe en `png/`. No usa fuentes, así que el resultado es idéntico en cualquier equipo. Los PNG ya generados están versionados; solo hay que regenerarlos si cambia el SVG.

### Editar el diseño

1. Cambia primero `logo/cercano-icon.svg` y los wordmarks si el símbolo cambia.
2. Actualiza el lienzo de origen: `source/design-canvas/Main.dc.html` repite el mismo `<svg>` del símbolo seis veces (logo claro, logo oscuro y los cuatro tamaños de icono de 128, 72, 40 y 24 px) y contiene los colores de la tabla de la sección 2. Mantén todo sincronizado.
3. Vuelve a ejecutar `export_icons.py`.
4. Registra el cambio en el PR y avisa al Coordinador si afecta a F1-07, F3-01 o F4.

### Exportar el wordmark como imagen

Los SVG de wordmark guardan «cercano» como texto, así que muestran Manrope solo si la fuente está instalada; si no, se ve una sans-serif de respaldo, como en la vista previa del repositorio. Para producir un PNG o un SVG con el texto convertido a trazos, abre el lienzo de origen en Claude Design y usa su opción de exportar, o instala Manrope y exporta desde un navegador. No se versionan PNG de wordmark por esta razón.

### Abrir el lienzo de origen

`source/design-canvas/` guarda los dos archivos de proyecto del lienzo (`canvas.json` y `Main.dc.html`). Para continuar editándolo en Claude Design, usa el lienzo original «Logo Cercano» de la cuenta de la persona responsable; los archivos de esta carpeta sirven de copia de respaldo y como referencia para los valores exactos de color, tamaño y trazo.

## 6. Licencia de los activos de marca

Los archivos de esta carpeta son parte de Cercano y siguen la licencia del repositorio (AGPL-3.0, ver `LICENSE` y `NOTICE`). El nombre y el logo «Cercano» son una marca del proyecto; usar el código de Cercano no concede derecho a usar su nombre ni su logo en productos derivados. Este párrafo es una propuesta y se confirmará con la política de marca de la decisión **D1** del roadmap.
