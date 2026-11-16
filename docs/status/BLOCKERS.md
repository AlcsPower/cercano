# Bloqueos abiertos

Formato: un bloque por bloqueo. Quien lo detecta lo registra; el Coordinador lo resuelve o lo escala al dueño.

### B-002 — El instalador `.exe`/`.msi` no abre: no existe un cliente Windows real

- **Estado:** abierto · **Detectado:** 2026-11-16 (dueño) · **Severidad:** alta · **Afecta:** M2, F4-07 (la consola genera artefactos no funcionales), F4.5 (el chat va en el cliente), F7
- **Causa:** `vendor/client` es el cliente RustDesk (Flutter + Rust + códecs C++ por vcpkg). Nunca se compiló para Windows: el CI (`base-binary.yml`) corre en Linux y `dist/base/cercano.exe` no existe. Sin `--base-binary`, `cercano-build` empaqueta un stub PE de 512 bytes sin código máquina y lo entrega como instalador válido. No es un problema de licencias.
- **Error del Coordinador:** el cierre de F3 dio por cumplido «instalador Windows» validando el empaquetado, la firma y los metadatos, pero no que el binario arrancara. Se corrige en `F3-cierre.md` y `README.md`.
- **Resolución:** F3-19 (cliente Windows en CI), F3-20 (fail-closed, prioridad inmediata: es un cambio pequeño) y F3-21 (prueba de humo). Mientras tanto, los artefactos generados son solo de prueba.
- **Hallazgo 2026-11-16 (previo a Windows):** `cargo metadata` sobre `vendor/client/Cargo.toml` falla: *«Dependency 'hbb_common' has different source paths»*. El cliente declara `hbb_common` en `../server/libs/hbb_common` (parche 002) y también en `libs/hbb_common` (workspace y `[patch]`), un directorio inexistente porque upstream lo trae como submódulo. El cliente **nunca se ha compilado**, ni en Linux; `base-binary.yml` no corre en la rama de trabajo (solo en `feat/**`). Además el CI general falla en `cargo-deny`, `clippy` y la compilación del servidor.
- **Decisión del dueño (2026-11-16):** GitHub compila la base una vez por versión y el generador personaliza (instalador = base + perfil firmado); el repositorio pasa a ser público. Pendiente: confirmar el correo de autor del historial (ver informe al dueño) antes de publicar.


---

## Historial de bloqueos resueltos

### B-001 — `LICENSE` sigue siendo MIT; falta el texto oficial de AGPL-3.0

- **Estado:** resuelto · **Detectado:** 2026-11-05 · **Resuelto:** 2026-11-05
- **Resolución:** se incorporó el texto oficial de GNU Affero General Public License v3.0 en `LICENSE`, validado con `tools/check-license.sh` (661 líneas).
- **Desbloqueado:** F0-02 (importar upstream).
