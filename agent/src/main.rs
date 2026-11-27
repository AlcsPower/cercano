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

//! `cercano-agent`: Windows service and diagnostic CLI (ADR-015, F3.5-04).

mod logs;
mod platform;

use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// File whose presence marks an enrolled agent. Written by F3.5-05.
const ENROLLMENT_FILE: &str = "enrollment.json";
const MAX_TAIL: usize = 10_000;
const DIAG_LOG_LINES: usize = 500;

#[derive(Parser)]
#[command(name = "cercano-agent", version, about = "Agente Cercano (ADR-015)")]
struct Cli {
    /// Salida JSON (para `ConvertFrom-Json` en PowerShell)
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Instala y arranca el servicio CercanoAgent (administrador)
    Install,
    /// Detiene y elimina el servicio y su almacén (administrador)
    Uninstall,
    /// Punto de entrada del servicio; lo invoca Windows
    Run,
    /// Estado del agente
    Status,
    /// Prueba la conexión con el servidor fijado
    TestConnection,
    /// Política efectiva
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// Últimas líneas del log del agente
    Logs {
        #[arg(long, default_value_t = 50)]
        tail: usize,
    },
    /// Vincula el equipo con una configuración (administrador)
    Enroll {
        /// Código de configuración o ruta a cercano-org.json
        #[arg(long)]
        config: String,
    },
    /// Vuelve a vincular el equipo (administrador)
    ReEnroll {
        /// Código de configuración o ruta a cercano-org.json
        #[arg(long)]
        config: Option<String>,
    },
    /// Genera un archivo de diagnóstico sin secretos
    ExportDiagnostics {
        /// Ruta de salida (por defecto, en la carpeta actual)
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Muestra la política efectiva
    Show,
}

#[derive(Debug)]
pub enum CliError {
    NotImplemented(&'static str),
    RequiresAdmin(&'static str),
    Unsupported(&'static str),
    Failed(String),
}

impl CliError {
    fn code(&self) -> &'static str {
        match self {
            Self::NotImplemented(_) => "not_implemented",
            Self::RequiresAdmin(_) => "requires_admin",
            Self::Unsupported(_) => "unsupported_platform",
            Self::Failed(_) => "failed",
        }
    }

    fn exit_code(&self) -> u8 {
        match self {
            Self::Failed(_) => 1,
            Self::NotImplemented(_) => 3,
            Self::RequiresAdmin(_) => 4,
            Self::Unsupported(_) => 5,
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotImplemented(what) => write!(f, "{what}: no implementado en F3.5-04"),
            Self::RequiresAdmin(what) => {
                write!(f, "{what} exige una consola con derechos de administrador")
            }
            Self::Unsupported(msg) => f.write_str(msg),
            Self::Failed(msg) => f.write_str(msg),
        }
    }
}

fn require_admin(what: &'static str) -> Result<(), CliError> {
    if platform::is_admin() {
        Ok(())
    } else {
        Err(CliError::RequiresAdmin(what))
    }
}

/// Status readable by a standard user: the store itself is admin-only, so
/// what depends on it is `null`/`unknown` without elevation.
fn status() -> Result<Value, CliError> {
    let store = platform::store_dir()?;
    let readable = std::fs::read_dir(&store).is_ok();
    let state = match (readable, store.join(ENROLLMENT_FILE).is_file()) {
        (false, _) => "unknown",
        (true, true) => "enrolled",
        (true, false) => "unenrolled",
    };
    Ok(json!({
        "agent_version": env!("CARGO_PKG_VERSION"),
        "service": platform::service_state(),
        "state": state,
        "store_dir": store,
        "store_readable": readable,
        "is_admin": platform::is_admin(),
    }))
}

fn tail_logs(n: usize) -> Result<Value, CliError> {
    let dir = logs::log_dir(&platform::store_dir()?);
    let lines = logs::tail(&dir, n.min(MAX_TAIL)).map_err(|e| {
        CliError::Failed(format!(
            "no se pudo leer {} (los logs solo son legibles por administradores): {e}",
            dir.display()
        ))
    })?;
    Ok(json!({ "lines": lines }))
}

fn export_diagnostics(out: Option<PathBuf>) -> Result<Value, CliError> {
    let now = chrono::Utc::now();
    let store = platform::store_dir()?;
    let logs = match logs::tail(&logs::log_dir(&store), DIAG_LOG_LINES) {
        // Redact again on export: lines may predate a redaction rule.
        Ok(lines) => json!(lines.iter().map(|l| logs::redact(l)).collect::<Vec<_>>()),
        Err(e) => json!(format!(
            "logs no accesibles (ejecute como administrador para incluirlos): {e}"
        )),
    };
    let report = json!({
        "generated_at": now.to_rfc3339(),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "status": status()?,
        "logs": logs,
    });
    let path = out.unwrap_or_else(|| {
        PathBuf::from(format!(
            "cercano-agent-diagnostics-{}.json",
            now.format("%Y%m%dT%H%M%SZ")
        ))
    });
    let text = serde_json::to_string_pretty(&report).expect("JSON value serializes");
    write_new(&path, &text)?;
    Ok(json!({ "path": path, "bytes": text.len() }))
}

fn write_new(path: &Path, text: &str) -> Result<(), CliError> {
    std::fs::write(path, text)
        .map_err(|e| CliError::Failed(format!("no se pudo escribir {}: {e}", path.display())))
}

fn run(cmd: Cmd) -> Result<Value, CliError> {
    match cmd {
        Cmd::Install => {
            require_admin("install")?;
            platform::install()?;
            Ok(json!({ "installed": true, "service": platform::service_state() }))
        }
        Cmd::Uninstall => {
            require_admin("uninstall")?;
            platform::uninstall()?;
            Ok(json!({ "uninstalled": true }))
        }
        Cmd::Run => platform::run_service().map(|()| json!({})),
        Cmd::Status => status(),
        // No pinned server exists until enrollment (F3.5-05).
        Cmd::TestConnection => Err(CliError::NotImplemented("test-connection")),
        Cmd::Policy {
            cmd: PolicyCmd::Show,
        } => Err(CliError::NotImplemented("policy show")),
        Cmd::Logs { tail } => tail_logs(tail),
        Cmd::Enroll { .. } => {
            require_admin("enroll")?;
            Err(CliError::NotImplemented("enroll"))
        }
        Cmd::ReEnroll { .. } => {
            require_admin("re-enroll")?;
            Err(CliError::NotImplemented("re-enroll"))
        }
        Cmd::ExportDiagnostics { out } => export_diagnostics(out),
    }
}

fn print_human(value: &Value) {
    match value.get("lines").and_then(Value::as_array) {
        Some(lines) => lines
            .iter()
            .filter_map(Value::as_str)
            .for_each(|l| println!("{l}")),
        None => {
            for (k, v) in value.as_object().into_iter().flatten() {
                match v {
                    Value::String(s) => println!("{k}: {s}"),
                    other => println!("{k}: {other}"),
                }
            }
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.cmd) {
        Ok(value) => {
            if cli.json {
                println!("{value}");
            } else {
                print_human(&value);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            if cli.json {
                println!(
                    "{}",
                    json!({ "error": { "code": e.code(), "message": e.to_string() } })
                );
            } else {
                eprintln!("error: {e}");
            }
            ExitCode::from(e.exit_code())
        }
    }
}
