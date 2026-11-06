# Informe de Resolución de Auditoría: H2, H3, H7 (y H9)

```
ID: AUDIT-H2-H3-H7     Agente: Agente-ControlPlane     Estado: Hecho
Qué se hizo:
  1. H3: Desacoplado el bloqueo de fuerza bruta en auth.rs consultando username e IP por separado sin condición OR que bloquee a toda la red o a 127.0.0.1. Se extrae la IP real del socket vía `ConnectInfo<SocketAddr>` y solo se confía en proxies si provienen de loopback (127.0.0.1 o ::1).
  2. H2: En devices.rs se registra la IP real del socket de conexión en lugar de la IP reportada en el JSON, se aplican límites de tamaño a todos los campos del payload y se implementa rate-limiting (mínimo 1 segundo entre latidos por dispositivo).
  3. H7: En devices.rs se preserva el nombre asignado previamente cuando un heartbeat posterior llega sin campo name o con cadena vacía/espacios.
  4. H9: Se fortalecieron los parámetros de Argon2id (m=65536, t=3, p=4) y se prefijaron los tokens de sesión con `cercano_sess_`.
Evidencia:
  - `cargo fmt --check`: OK (código formateado con rustfmt)
  - `cargo clippy -- -D warnings`: OK (0 advertencias)
  - `cargo test`: 48 tests pasados, 0 fallados, 0 ignorados.
    * tests::test_failed_logins_on_one_ip_do_not_block_different_ip: OK
    * tests::test_heartbeat_without_name_preserves_existing_name: OK
    * tests::test_heartbeat_ip_comes_from_connection_not_json_spoofing: OK
    * tests::test_heartbeat_rate_limiting_throttles_rapid_requests: OK
    * auth::tests::test_argon2id_hashing_and_verification: OK
    * auth::tests::test_extract_client_ip: OK
    * devices::tests::test_validate_heartbeat_input_field_length_limits: OK
Desviaciones:
  - Ninguna. Se incorporó adicionalmente el requerimiento H9 solicitado por el Coordinador.
Riesgos / deuda:
  - Ninguno.
Siguiente paso sugerido:
  - Fusión de la rama `fix/audit-H2-H3-H7-auth-devices` a la rama principal previa revisión de QA.
```
