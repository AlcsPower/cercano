# Reescritura del historial (2026-11-16)

**Motivo:** retirar datos personales e institucionales antes de publicar el repositorio.

**Qué se cambió:** (1) autores y committers con correos personales o institucionales pasan a `Alcs <alcs@users.noreply.github.com>`; (2) rutas locales de Windows/WSL y el dominio institucional de ejemplo se reemplazaron por valores genéricos (`example.org`, `usuario`); (3) el nombre de la institución en datos de prueba y documentos pasó a «Institución de Ejemplo» y `MIFIC` a `ACME`, en ambos lados de cada aserción, de modo que las pruebas no cambian de resultado. El árbol de la rama quedó igual salvo dos archivos de ejemplo.

**Verificación:** sin ocurrencias de los correos ni de las cadenas privadas en identidades, mensajes ni contenido de `main`, `docs/F0-01-gobernanza` y `docs/F8-01-portabilidad-bd`.

**Efectos:** todos los hashes cambiaron. Los clones existentes deben descartarse: `git fetch origin && git checkout docs/F0-01-gobernanza && git reset --hard origin/docs/F0-01-gobernanza`. No se debe hacer `merge` ni `push` desde un clon anterior (reintroduciría el historial viejo).

**Pendiente (no se puede hacer desde la API de la sesión):** las referencias `refs/pull/1/head` y `refs/pull/2/head` de los PR cerrados conservan los commits viejos y serían visibles al hacer público el repositorio; hay que pedir su purga a GitHub Support o recrear el repositorio. La rama `docs/F8-01-portabilidad-bd` quedó reescrita pero debe borrarse desde la interfaz de GitHub. Quedan rutas del tipo `C:\Users\alcs\OneDrive - cercano.local\...` en informes antiguos (inocuas; nombre de usuario público).
