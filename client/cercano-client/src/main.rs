// Copyright (C) 2026 Cercano Contributors
//
// This file is part of Cercano.
//
// Cercano is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::File;
use std::io::{BufRead, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedProfileContainer {
    pub schema_version: Option<String>,
    pub key_id: Option<String>,
    pub signature: Option<String>,
    pub profile: ProfilePayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilePayload {
    pub profile_id: Option<String>,
    pub role: Option<String>,
    pub server: Option<ServerConfig>,
    pub identity: Option<IdentityConfig>,
    pub policy: Option<PolicyConfig>,
    pub installation: Option<InstallationConfig>,
    pub identification: Option<IdentificationConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub rendezvous_server: Option<String>,
    pub relay_server: Option<String>,
    pub api_server: Option<String>,
    pub server_public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    pub app_name: Option<String>,
    pub about_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub allow_incoming: Option<bool>,
    pub allow_outgoing: Option<bool>,
    pub unattended_access: Option<bool>,
    pub require_approval: Option<bool>,
    pub allow_file_transfer: Option<bool>,
    pub allow_terminal: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallationConfig {
    pub mode: Option<String>,
    pub install_path: Option<String>,
    pub auto_start: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentificationConfig {
    pub device_group: Option<String>,
    pub default_owner: Option<String>,
}

fn main() {
    println!();
    println!("  ================================================================");
    println!("     C E R C A N O  --  A S I S T E N C I A   R E M O T A       ");
    println!("                 Cliente Ligero Oficial (AGPL-3.0)              ");
    println!("  ================================================================");
    println!();

    // 1. Cargar perfil firmado
    let (profile, profile_source) = load_profile();

    let app_name = profile
        .identity
        .as_ref()
        .and_then(|i| i.app_name.clone())
        .unwrap_or_else(|| "Cercano Asistencia".to_string());
    let role = profile
        .role
        .clone()
        .unwrap_or_else(|| "soporte".to_string())
        .to_uppercase();
    let profile_id = profile
        .profile_id
        .clone()
        .unwrap_or_else(|| "0192e300-local".to_string());

    println!("  [+] Rol activo:        {} ({})", app_name, role);
    println!("  [+] ID de perfil:      {}", profile_id);
    println!("  [+] Origen del perfil: {}", profile_source);

    if let Some(id_cfg) = &profile.identification {
        if let Some(grp) = &id_cfg.device_group {
            println!("  [+] Grupo asignado:    {}", grp);
        }
        if let Some(owner) = &id_cfg.default_owner {
            println!("  [+] Propietario TI:    {}", owner);
        }
    }

    let default_rendezvous = "172.16.8.163:21116".to_string();
    let default_relay = "172.16.8.163:21117".to_string();
    let default_api = "http://172.16.8.163:21114".to_string();

    let server = profile.server.as_ref();
    let rendezvous = server
        .and_then(|s| s.rendezvous_server.clone())
        .unwrap_or(default_rendezvous);
    let relay = server
        .and_then(|s| s.relay_server.clone())
        .unwrap_or(default_relay);
    let api = server
        .and_then(|s| s.api_server.clone())
        .unwrap_or(default_api);

    println!();
    println!("  ----------------------------------------------------------------");
    println!("  DIAGNÓSTICO DE CONECTIVIDAD CON INFRAESTRUCTURA CERCANO");
    println!("  ----------------------------------------------------------------");

    run_diagnostics(&rendezvous, &relay, &api);

    println!();
    println!("  ----------------------------------------------------------------");
    println!("  POLÍTICAS DE ASISTENCIA ACTIVAS");
    println!("  ----------------------------------------------------------------");
    if let Some(p) = &profile.policy {
        println!(
            "  * Conexiones entrantes:     {}",
            if p.allow_incoming.unwrap_or(true) {
                "PERMITIDAS"
            } else {
                "BLOQUEADAS"
            }
        );
        println!(
            "  * Conexiones salientes:     {}",
            if p.allow_outgoing.unwrap_or(false) {
                "PERMITIDAS"
            } else {
                "BLOQUEADAS (Restringido)"
            }
        );
        println!(
            "  * Aprobación obligatoria:   {}",
            if p.require_approval.unwrap_or(true) {
                "SÍ (Consentimiento requerido)"
            } else {
                "NO"
            }
        );
        println!(
            "  * Transferencia de archivos: {}",
            if p.allow_file_transfer.unwrap_or(true) {
                "HABILITADA"
            } else {
                "DESHABILITADA"
            }
        );
        println!(
            "  * Terminal remota de cmd:   {}",
            if p.allow_terminal.unwrap_or(false) {
                "HABILITADA"
            } else {
                "DESHABILITADA"
            }
        );
    }

    println!();
    println!("  ================================================================");
    println!("  [R] Reintentar diagnóstico    [H] Enviar latido    [Q] Salir");
    println!("  ================================================================");

    interactive_loop(&rendezvous, &relay, &api);
}

fn run_diagnostics(rendezvous: &str, relay: &str, api: &str) {
    print!("  * Servidor Rendezvous ({}): ", rendezvous);
    std::io::stdout().flush().unwrap();
    match test_tcp_connect(rendezvous, Duration::from_millis(1500)) {
        Ok(_) => println!("[EN LÍNEA / CONECTADO]"),
        Err(e) => println!("[NO RESPONDE] ({})", e),
    }

    print!("  * Servidor Relay      ({}): ", relay);
    std::io::stdout().flush().unwrap();
    match test_tcp_connect(relay, Duration::from_millis(1500)) {
        Ok(_) => println!("[EN LÍNEA / CONECTADO]"),
        Err(e) => println!("[NO RESPONDE] ({})", e),
    }

    print!("  * Servidor API Control({}): ", api);
    std::io::stdout().flush().unwrap();
    match test_http_api(api, Duration::from_millis(1500)) {
        Ok(status) => println!("[EN LÍNEA / HTTP {}]", status),
        Err(e) => println!("[NO RESPONDE] ({})", e),
    }
}

fn interactive_loop(rendezvous: &str, relay: &str, api: &str) {
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut line = String::new();

    loop {
        print!("\n  Ingrese opción (R/H/Q): ");
        std::io::stdout().flush().unwrap();
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break, // EOF o error
            Ok(_) => {}
        }
        let choice = line.trim().to_uppercase();
        match choice.as_str() {
            "R" => {
                println!("\n  Re-ejecutando diagnóstico de red...");
                run_diagnostics(rendezvous, relay, api);
            }
            "H" => {
                println!("\n  Enviando latido de telemetría a {}...", api);
                match test_http_api(api, Duration::from_millis(2000)) {
                    Ok(_) => println!("  [OK] Latido registrado exitosamente en el servidor."),
                    Err(e) => println!("  [ERROR] No se pudo enviar el latido: {}", e),
                }
            }
            "Q" | "EXIT" | "SALIR" => {
                println!("\n  Finalizando agente Cercano...");
                break;
            }
            _ => {
                println!(
                    "  Opción no reconocida. Utilice R (Reintentar), H (Heartbeat) o Q (Salir)."
                );
            }
        }
    }
}

fn test_tcp_connect(addr_str: &str, timeout: Duration) -> Result<(), String> {
    let addrs: Vec<SocketAddr> = addr_str
        .to_socket_addrs()
        .map_err(|e| format!("Resolución DNS fallida: {}", e))?
        .collect();

    for addr in addrs {
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            return Ok(());
        }
    }
    Err("Conexión rechazada o tiempo de espera agotado".to_string())
}

fn test_http_api(api_url: &str, timeout: Duration) -> Result<u16, String> {
    let stripped = api_url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let parts: Vec<&str> = stripped.split('/').collect();
    let host_port = parts[0];

    let host_parts: Vec<&str> = host_port.split(':').collect();
    let host = host_parts[0];
    let port: u16 = if host_parts.len() > 1 {
        host_parts[1].parse().unwrap_or(80)
    } else {
        80
    };

    let addr_str = format!("{}:{}", host, port);
    let socket_addrs: Vec<SocketAddr> = addr_str
        .to_socket_addrs()
        .map_err(|e| format!("DNS: {}", e))?
        .collect();

    for addr in socket_addrs {
        if let Ok(mut stream) = TcpStream::connect_timeout(&addr, timeout) {
            let req = format!(
                "GET /healthz HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                host
            );
            if stream.write_all(req.as_bytes()).is_ok() {
                let mut resp = String::new();
                let _ = stream.read_to_string(&mut resp);
                if let Some(status_line) = resp.lines().next() {
                    let tokens: Vec<&str> = status_line.split_whitespace().collect();
                    if tokens.len() >= 2 {
                        if let Ok(code) = tokens[1].parse::<u16>() {
                            return Ok(code);
                        }
                    }
                }
                return Ok(200);
            }
        }
    }
    Err("No se pudo conectar al endpoint /healthz".to_string())
}

fn load_profile() -> (ProfilePayload, String) {
    let candidates = vec![
        (
            PathBuf::from("cercano-profile.signed.json"),
            "directorio de trabajo",
        ),
        (
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("cercano-profile.signed.json")))
                .unwrap_or_default(),
            "directorio del ejecutable",
        ),
        (
            PathBuf::from(r"C:\Program Files\Cercano Soporte\cercano-profile.signed.json"),
            "instalación residente soporte",
        ),
        (
            PathBuf::from(r"C:\Program Files\Cercano Tecnico\cercano-profile.signed.json"),
            "instalación residente técnico",
        ),
    ];

    for (path, label) in candidates {
        if path.is_file() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(payload) = parse_profile_json(&content) {
                    return (payload, format!("{} ({})", label, path.display()));
                }
            }
        }
    }

    // Intentar leer desde el ZIP incrustado en el propio binario
    if let Ok(exe_path) = std::env::current_exe() {
        if let Ok(file) = File::open(&exe_path) {
            if let Ok(mut archive) = zip::ZipArchive::new(file) {
                if let Ok(mut profile_file) = archive.by_name("cercano-profile.signed.json") {
                    let mut content = String::new();
                    if profile_file.read_to_string(&mut content).is_ok() {
                        if let Ok(payload) = parse_profile_json(&content) {
                            return (
                                payload,
                                format!("ZIP incrustado en ejecutable ({})", exe_path.display()),
                            );
                        }
                    }
                }
            }
        }
    }

    // Perfil de respaldo predeterminado para LAN
    (
        ProfilePayload {
            profile_id: Some("0192e300-lan-fallback".to_string()),
            role: Some("soporte".to_string()),
            server: Some(ServerConfig {
                rendezvous_server: Some("172.16.8.163:21116".to_string()),
                relay_server: Some("172.16.8.163:21117".to_string()),
                api_server: Some("http://172.16.8.163:21114".to_string()),
                server_public_key: None,
            }),
            identity: Some(IdentityConfig {
                app_name: Some("Cercano Soporte LAN".to_string()),
                about_text: Some("Cercano Soporte LAN - AGPL-3.0".to_string()),
            }),
            policy: Some(PolicyConfig {
                allow_incoming: Some(true),
                allow_outgoing: Some(false),
                unattended_access: Some(false),
                require_approval: Some(true),
                allow_file_transfer: Some(true),
                allow_terminal: Some(false),
            }),
            installation: None,
            identification: Some(IdentificationConfig {
                device_group: Some("Soporte-LAN".to_string()),
                default_owner: Some("admin@cercano.lan".to_string()),
            }),
        },
        "Perfil predeterminado LAN (172.16.8.163)".to_string(),
    )
}

fn parse_profile_json(json_str: &str) -> Result<ProfilePayload, String> {
    if let Ok(container) = serde_json::from_str::<SignedProfileContainer>(json_str) {
        return Ok(container.profile);
    }
    if let Ok(payload) = serde_json::from_str::<ProfilePayload>(json_str) {
        return Ok(payload);
    }
    Err("Estructura JSON no reconocida".to_string())
}
