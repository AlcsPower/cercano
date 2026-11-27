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

//! F3.5-04 CLI tests. Off Windows the store comes from `CERCANO_AGENT_DIR`, so
//! they run in CI against a temporary store as a non-administrator. On Windows
//! the CLI uses the real `%ProgramData%` store; it is verified by hand (see
//! `docs/status/informes/F3.5-04.md`).
#![cfg(not(windows))]

use serde_json::Value;
use std::path::Path;
use std::process::Command;

fn agent(store: &Path, args: &[&str]) -> (i32, Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_cercano-agent"))
        .args(args)
        .arg("--json")
        .env("CERCANO_AGENT_DIR", store)
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let value = serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{args:?}: {e}: {stdout}"));
    (out.status.code().unwrap(), value)
}

#[test]
fn status_is_json_and_needs_no_admin() {
    let store = tempfile::tempdir().unwrap();
    let (code, v) = agent(store.path(), &["status"]);
    assert_eq!(code, 0);
    assert_eq!(v["state"], "unenrolled");
    assert_eq!(v["is_admin"], false);
    assert_eq!(v["service"], "unsupported_platform");
    assert_eq!(v["agent_version"], env!("CARGO_PKG_VERSION"));

    let (_, v) = agent(&store.path().join("missing"), &["status"]);
    assert_eq!(v["state"], "unknown");
}

#[test]
fn state_changing_commands_require_admin() {
    let store = tempfile::tempdir().unwrap();
    for args in [
        &["re-enroll"][..],
        &["enroll", "--config", "eyJ9"],
        &["install"],
        &["uninstall"],
    ] {
        let (code, v) = agent(store.path(), args);
        assert_eq!(code, 4, "{args:?}");
        assert_eq!(v["error"]["code"], "requires_admin", "{args:?}");
    }
}

#[test]
fn commands_without_backend_say_so() {
    let store = tempfile::tempdir().unwrap();
    for args in [&["policy", "show"][..], &["test-connection"]] {
        let (code, v) = agent(store.path(), args);
        assert_eq!(code, 3, "{args:?}");
        assert_eq!(v["error"]["code"], "not_implemented");
        let msg = v["error"]["message"].as_str().unwrap();
        assert!(msg.contains("no implementado en F3.5-04"), "{msg}");
    }
}

#[test]
fn logs_tail() {
    let store = tempfile::tempdir().unwrap();
    let logs = store.path().join("logs");
    std::fs::create_dir_all(&logs).unwrap();
    std::fs::write(logs.join("agent.log"), "uno\ndos\ntres\n").unwrap();
    let (code, v) = agent(store.path(), &["logs", "--tail", "2"]);
    assert_eq!(code, 0);
    assert_eq!(v["lines"], serde_json::json!(["dos", "tres"]));
}

/// Base64/hex runs that look like keys or tokens (same rule as the logger).
fn secret_like_runs(text: &str) -> Vec<&str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || "+/=_-".contains(c)))
        .filter(|run| {
            let mixed = run.chars().any(|c| c.is_ascii_uppercase())
                && run.chars().any(|c| c.is_ascii_lowercase())
                && run.chars().any(|c| c.is_ascii_digit());
            (run.len() >= 32 && mixed)
                || (run.len() >= 40 && run.chars().all(|c| c.is_ascii_hexdigit()))
        })
        .collect()
}

/// TC-F3.5-013: secrets planted straight into the log file (bypassing the
/// logger's redaction) do not reach the diagnostics export.
#[test]
fn export_diagnostics_has_no_secrets() {
    let store = tempfile::tempdir().unwrap();
    let logs = store.path().join("logs");
    std::fs::create_dir_all(&logs).unwrap();
    let secrets = [
        "EJEMPLO_token_de_registro_soporte_000000001",
        "Q2VyY2Fub0VqZW1wbG9DbGF2ZVB1YmxpY2EwMDAwMDE=",
        "c2VjcmV0bzE",
        "hunter2",
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    ];
    std::fs::write(
        logs.join("agent.log"),
        format!(
            "2026-11-25T10:00:00Z INFO servicio iniciado (versión 0.1.0), almacén C:\\Users\\José\n\
             2026-11-25T10:00:01Z INFO enroll_token={}\n\
             2026-11-25T10:00:02Z INFO clave fijada {}\n\
             2026-11-25T10:00:03Z WARN Authorization: Bearer {}\n\
             2026-11-25T10:00:04Z WARN {{\"password\": \"{}\"}}\n\
             2026-11-25T10:00:05Z INFO device private key {}\n",
            secrets[0], secrets[1], secrets[2], secrets[3], secrets[4]
        ),
    )
    .unwrap();
    let out = store.path().join("diag.json");
    let (code, v) = agent(
        store.path(),
        &["export-diagnostics", "--out", out.to_str().unwrap()],
    );
    assert_eq!(code, 0, "{v}");
    let text = std::fs::read_to_string(&out).unwrap();
    for s in secrets {
        assert!(!text.contains(s), "secret leaked: {s}");
    }
    assert_eq!(secret_like_runs(&text), Vec::<&str>::new());
    let report: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(report["status"]["state"], "unenrolled");
    assert_eq!(report["logs"].as_array().unwrap().len(), 6);
    assert!(text.contains("servicio iniciado"));
}
