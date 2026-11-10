# Spike S7: Topologías LAN, relays y transporte

- **ID de Spike:** S7
- **Tarea asociada:** F6-01
- **Fecha:** 2026-11-10
- **Rol:** Agente-Servidor + Agente-Seguridad
- **Estado:** En verificación — diseño, umbrales, amenazas y **medición de red** hechos; la medición de sesión depende de F6-05/F6-06 (ver §10)
- **Criterios de aceptación:** plan F6-01 (informe reproducible) y TC-F6-001…020

---

## 1. Objetivo

Comparar las rutas de conexión de Cercano (directa, relay único y multi-relay, y WebSocket
como evaluación) con métricas acordadas **antes** de medir, y dejar fijado qué debe demostrar la
medición para aprobar cada una. Este documento es la referencia del spike; el informe con los
números va en `docs/status/informes/F6-01.md`.

Hipótesis a contrastar:

1. La conexión directa es viable y preferible en LAN y en NAT con *hole punching*.
2. Un relay único cubre redes con UDP bloqueado sin degradar la experiencia por encima de los
   umbrales de §3.
3. Con dos relays, la selección por salud/latencia no oscila y el fallback no rompe la sesión.
4. WebSocket solo se justifica si la medición demuestra un escenario corporativo que hoy no conecta
   (§7); no se implementa por paridad.

## 2. Topologías y rutas

| Ruta | Descripción | Qué se mide |
|---|---|---|
| A. Directa | `hbbs` intercambia candidatos; UDP *hole punching* entre clientes | Establecimiento, RTT, jitter, pérdida, throughput |
| B. Relay único | `hbbr` reenvía el flujo cifrado extremo a extremo | Idem + CPU/RAM del nodo y capacidad |
| C. Multi-relay | Dos `hbbr` con distinta latencia; el selector elige uno | Idem + estabilidad de selección y fallback |
| D. WebSocket | Puerto 443 a través de proxy inverso | Solo si §7 lo justifica: establecimiento, corte, auth |

Topología del laboratorio: un `hbbs`, dos `hbbr`, dos clientes Cercano en la misma LAN (o con NAT
controlado), mismo hardware para todas las rutas. La baseline es la medición de F5 con la misma
versión de cliente.

## 3. Métricas y umbrales (acordados antes de medir)

| Métrica | Instrumento | Objetivo |
|---|---|---|
| Tiempo de establecimiento p50/p95 | Marca de tiempo del cliente (inicio → sesión lista) | Directa ≤ 2 s / 4 s; relay ≤ 3 s / 6 s; tras fallback ≤ 7 s |
| RTT p50/p95 | Sonda de aplicación cada 1 s durante 60 s | Relay p95 ≤ 3× directa y ≤ 120 ms en LAN |
| Jitter | Desviación del RTT | ≤ 30 ms |
| Pérdida | Sondas perdidas en 60 s | ≤ 1 % |
| Throughput | Transferencia de 100 MB | ≥ 80 % de la directa |
| CPU/RAM del relay | `docker stats` o equivalente | ≤ 50 % de un núcleo y ≤ 200 MB con 10 sesiones |
| Capacidad | Sesiones hasta degradar el p95 2× o pérdida > 2 % | Registrar el número; objetivo ≥ 50 en LAN gigabit |
| Conmutación UDP→relay | Bloquear UDP en el cliente | ≤ 10 s, sin duplicar sesión ni evento de auditoría |
| Fallback relay caído | Detener el relay elegido | ≤ 5 s al siguiente, mismo `trace_id` |
| Estabilidad de selección | 10 minutos de sesión estable | No cambia de relay si la mejora es < 20 % (histéresis de 3 muestras) |

Reglas de medición: 3 repeticiones por escenario, se reporta la mediana y el p95; la misma carga y
los mismos equipos entre rutas; se anotan versión de cliente/servidor y configuración exacta. Un
objetivo incumplido no se «ajusta después»: se reporta y el Coordinador decide si el umbral cambia,
con el motivo escrito.

## 4. Método

1. Levantar el laboratorio (`tests/lab/docker-compose.yml`) con `hbbs` y dos `hbbr`.
2. Medir A (directa) como baseline: establecimiento ×10, sesión de 60 s ×3, transferencia ×3.
3. Forzar B (relay): bloquear UDP en el cliente con regla de firewall local; repetir la batería.
4. Medir C: dos relays con latencia distinta (regla de red local); verificar selección, histéresis y
   fallback deteniendo el relay elegido.
5. Repetir la batería con 10 sesiones concurrentes para CPU/RAM y capacidad.
6. Registrar en crudo (CSV/JSON) y resumir contra §3.
7. Solo laboratorio propio; nunca sistemas de terceros.

## 5. Compatibilidad

| Cliente | Directa | Relay | UDP bloqueado | Notas |
|---|---|---|---|---|
| Cercano 1.5.1 (base actual) | sí | sí | sí | Versión de referencia del spike |
| Cercano anterior soportado | sí | sí | sí | Debe seguir funcionando tras F6-05 |
| Cliente upstream sin perfil | referencia | referencia | referencia | No soportado en v1; no se promete |
| IPv6 | no en v1 | no en v1 | — | Se documenta como límite |
| Proxy HTTP corporativo | no | no | no | Solo si §7 aprueba WebSocket |

Compatibilidad de protocolo: no se cambia el protocolo upstream. Cualquier ajuste va en parche aislado
y registrado en `patches/INDEX.md` (F6-03/F6-04).

## 6. Autenticación de relays (entrada para F6-02)

**Decisión:** el cliente confía en la lista de relays porque viene en la respuesta **firmada** de
`hbbs` (clave Ed25519 del servidor, ya verificada por el cliente). Por tanto:

- Los relays son endpoints **fijados por el administrador**; `hbbs` solo anuncia los registrados.
  Un relay no registrado no se anuncia ni se selecciona (lo implementa F6-02 con tabla de relays y
  validación; F6-04 añade salud y retiro).
- **No se añade autenticación criptográfica por relay** al protocolo: rompería compatibilidad y no
  aporta confidencialidad, porque el contenido ya es extremo a extremo y el relay no lo descifra.
- Límite explícito y aceptado: quien controle el host o el DNS de un relay puede **denegar servicio o
  ver metadatos** (volumen, tiempos, IPs), nunca el contenido. Se mitiga con allowlist administrada,
  salud, revocación y auditoría de cambios, no con criptografía nueva.
- Si en el futuro se exige identidad fuerte por relay, es pinning de clave pública por relay con
  handshake propio: cambio de protocolo, ADR aparte y fuera de F6.

## 7. Criterio para WebSocket (entrada para F6-07)

Se implementa solo si la medición demuestra **las dos** condiciones:

1. Un escenario soportado (cliente corporativo tras proxy que solo permite 443/TCP) donde hoy la
   sesión no se establece ni por directa ni por relay.
2. La ruta WebSocket pasa autenticación, TLS, límites y corte de proxy **sin abrir ninguna vía que
   evite consentimiento, rol o revocación**, y tiene *fallback* probado.

Si no se cumplen, se difiere con el ADR de F6-07 y los números de §3 como evidencia.

## 8. Amenazas y mitigaciones

| Amenaza | Impacto | Mitigación |
|---|---|---|
| Descubrimiento filtra inventario o amplía superficie | Alto | Opt-in, rangos/interfaces explícitos, sin credenciales ni listas globales (F6-03) |
| Anuncio descubierto otorga confianza | Alto | Un anuncio solo sirve para intentar la conexión normal; claves, consentimiento y rol se validan igual |
| Relay hostil o suplantado | Medio | Contenido E2E; endpoints fijados por el servidor firmado; límite documentado (§6) |
| Relay no registrado seleccionado | Medio | Allowlist administrada y validación en `hbbs` (F6-02) |
| Cambio de ruta reinicia consentimiento o privilegios | Alto | Consentimiento y rol ligados a la sesión; revalidación en servidor (F6-06) |
| Reintentos duplican sesiones o eventos | Medio | `trace_id` estable; deduplicación por nonce ya existente |
| Métricas de ruta exponen datos personales | Medio | Agregados por sitio/relay, sin contenido, tokens ni IPs completas (F6-08) |
| WebSocket se convierte en vía de bypass del proxy | Alto | ADR con pruebas de proxy, auth y corte; si no, no se implementa (§7) |

## 9. Qué debe demostrar el informe

- Tabla resultado vs objetivo de §3 por ruta, con medianas y p95 de las 3 repeticiones.
- Configuración exacta (versiones, hosts, reglas de red) y comandos ejecutables por otra persona.
- Veredicto por ruta: cumple / no cumple, con el motivo; y decisión de WebSocket (§7).
- Evidencia de que la conmutación no duplica sesiones ni eventos de auditoría.

## 10. Medición realizada y límites

**Medido (2026-11-10, laboratorio real):** RTT/jitter/pérdida de directa, un salto y dos saltos de
relay; throughput TCP directo, con 20 ms ±5 ms y 1 % de pérdida, y con 100 ms ±20 ms; consumo del nodo
relay en reposo y con 10 conexiones. Resultados y evaluación en
[`docs/status/informes/F6-01.md`](../status/informes/F6-01.md) §3–§4. Hallazgo principal: **la
pérdida domina** (1 % de pérdida a 20 ms de RTT deja el TCP en 0,7–0,9 MB/s), y el criterio «3× la
directa» no es informativo por debajo de 10 ms; se propone un suelo absoluto que decide el Coordinador.

**No medible todavía:** establecimiento y RTT de sesión, capacidad real y coste de reenvío de `hbbr`
con tráfico (necesitan el cliente con sesión y el selector de F6-05); conmutación y fallback (F6-05/06);
WebSocket (F6-07 y un proxy corporativo real). Los umbrales de §3 son de LAN y no se extrapolan a WAN.
