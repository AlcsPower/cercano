# cercano-agent

Agente Cercano para Windows (ADR-015): servicio `CercanoAgent` sin interfaz que, en fases siguientes,
vincula el equipo con el servidor de la organización y sirve configuración, rol, política, chat y
auditoría a la aplicación por el canal local ([`docs/specs/agente-ipc.md`](../docs/specs/agente-ipc.md)).

**Estado (F3.5-04): esqueleto.** Servicio, almacén, logs y CLI de diagnóstico. La vinculación
(F3.5-05), el canal local (F3.5-06) y la política (F3.5-07) aún no existen: los comandos que dependen
de ellos responden «no implementado en F3.5-04» con código de salida 3.

## Comandos

Todos admiten `--json` (para `ConvertFrom-Json`). Los marcados con † exigen una consola de administrador.

| Comando | Qué hace hoy |
|---|---|
| `install` † | Crea el servicio `CercanoAgent` (`LocalSystem`, inicio automático, `cercano-agent.exe run`), crea el almacén y arranca el servicio. El ejecutable debe estar dentro de `%ProgramFiles%` |
| `uninstall` † | Detiene y elimina el servicio y borra el almacén (incluidos los logs) |
| `run` | Punto de entrada del servicio; lo invoca Windows, no una persona |
| `status` | Versión, estado del servicio, estado de vinculación (`unknown` si el almacén no es legible sin administrador) |
| `test-connection` | No implementado en F3.5-04 (no hay servidor fijado hasta F3.5-05) |
| `policy show` | No implementado en F3.5-04 (F3.5-07) |
| `logs --tail N` | Últimas N líneas del log (máximo 10 000). Requiere administrador por la ACL del almacén |
| `enroll --config <código o ruta>` † | No implementado en F3.5-04 (F3.5-05) |
| `re-enroll [--config …]` † | No implementado en F3.5-04 (F3.5-05) |
| `export-diagnostics [--out ruta]` | JSON con estado, sistema y últimas 500 líneas del log, redactadas de nuevo |

Códigos de salida: 0 correcto, 1 error, 2 uso incorrecto, 3 no implementado, 4 exige administrador,
5 plataforma no soportada. Con `--json`, un error sale como `{"error":{"code","message"}}` en la salida
estándar.

```powershell
cercano-agent status --json | ConvertFrom-Json
```

## Almacén y logs

- `%ProgramData%\Cercano\agent\` (ruta obtenida con `SHGetKnownFolderPath`, no de la variable de
  entorno). Propietario `Administradores`; DACL protegida `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`,
  aplicada a todo el árbol en cada `install` y arranque del servicio, así que una carpeta creada antes
  por otro usuario pierde su ACL.
- Logs en `logs\agent.log`, rotados al llegar a 1 MiB (`agent.log.1` … `agent.log.5`). Cada línea pasa
  por `logs::redact` (pares `token=`, `password:`, `Bearer …` y secuencias largas base64 o hex), y
  `export-diagnostics` vuelve a redactar al exportar.

## Plataformas

El código de Windows está tras `cfg(windows)`. En Linux el crate compila y sus pruebas corren en CI:
`install`, `uninstall` y `run` responden «plataforma no soportada», nadie es administrador y el
almacén se toma de `CERCANO_AGENT_DIR` (solo para pruebas).

## Pruebas

```powershell
cargo test -p cercano-agent
```

- `src/logs.rs`: redacción, rotación y lectura del final del log.
- `tests/cli.rs` (Linux): JSON de cada comando, administrador exigido, «no implementado» y
  `export-diagnostics` sin secretos (TC-F3.5-013).
- `tests/contract.rs`: contrato F3.5-03 (esquemas, ejemplos, operaciones solo de lectura, tamaño del
  código de configuración).

La instalación real del servicio se verifica a mano en Windows; ver
[`docs/status/informes/F3.5-04.md`](../docs/status/informes/F3.5-04.md).
