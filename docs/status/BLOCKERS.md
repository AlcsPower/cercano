# Bloqueos abiertos

Formato: un bloque por bloqueo. Quien lo detecta lo registra; el Coordinador lo resuelve o lo escala al dueño.

## B-001 — `LICENSE` sigue siendo MIT; falta el texto oficial de AGPL-3.0

- **Estado:** abierto · **Detectado:** 2026-11-05 · **Afecta a:** F0-02 y todo lo que importe código de `vendor/`
- **Causa:** el repositorio se creó con una licencia MIT. RustDesk y su servidor son AGPL-3.0, así que cualquier derivado que se publique debe distribuirse bajo AGPL-3.0. El entorno de los agentes no puede descargar el texto oficial (GitHub raw, gnu.org, PyPI y npm están bloqueados) y un texto legal no se reescribe de memoria.
- **Qué se necesita (lo hace el dueño del repo, 1 minuto):** cualquiera de estas dos vías.
  1. En GitHub: abrir `LICENSE` → **Edit** → **Choose a license template** → *GNU Affero General Public License v3.0* → *Review and submit* → confirmar el commit a una rama y abrir PR (o directo a `main`, si se prefiere).
  2. En local: `curl -fsSL https://www.gnu.org/licenses/agpl-3.0.txt -o LICENSE`, commit y push.
- **Cómo se comprueba:** `tools/check-license.sh` debe terminar con código 0. Comprueba que `LICENSE` contiene «GNU AFFERO GENERAL PUBLIC LICENSE» y «Version 3, 19 November 2007».
- **Qué se desbloquea:** F0-02 (importar upstream), y con ello F0-04, F0-05 y el resto de spikes.
- **Mientras tanto** pueden avanzar las tareas que no importan código de upstream: F0-03 (CI), F0-09 (laboratorio LAN), F1-03 (esqueleto de `cercano-api`) y el trabajo de `audit-core` que no depende del cliente.
