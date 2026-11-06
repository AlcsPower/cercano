// Copyright (C) 2026 Cercano Contributors
//
// This file is part of Cercano.
//
// Cercano is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Cercano is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Cercano. If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-only

use audit_core::{Actor, AuditStore, Category, EventInput, Outcome, Source, Subject};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serde_json::json;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn get_bin_path() -> String {
    env!("CARGO_BIN_EXE_cercano-audit").to_string()
}

async fn setup_test_audit_db() -> (tempfile::TempDir, String, SigningKey, String) {
    let dir = tempdir().expect("create tempdir");
    let db_path = dir.path().join("audit.sqlite");
    let db_url = format!("sqlite://{}", db_path.to_str().unwrap());
    let store = AuditStore::open_url(&db_url).await.expect("open db");

    let signing_key = SigningKey::generate(&mut OsRng);
    let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let pubkey_path = dir.path().join("audit.pub");
    fs::write(&pubkey_path, &pubkey_hex).expect("write pubkey");

    // Event 1
    store
        .append(EventInput::new(
            "trace-1",
            Source::Client,
            Category::Auth,
            "auth.login",
            Actor::new("user-admin"),
            Outcome::Success,
            json!({"method": "password"}),
        ))
        .await
        .unwrap();

    // Event 2
    store
        .append(
            EventInput::new(
                "trace-1",
                Source::Client,
                Category::Conn,
                "conn.start",
                Actor::new("user-admin"),
                Outcome::Success,
                json!({"client_ip": "192.168.1.100"}),
            )
            .with_subject(Subject::new("device-win11")),
        )
        .await
        .unwrap();

    // Checkpoint 1 (covers events 1 & 2)
    store
        .create_checkpoint(&signing_key, "key-audit-2026")
        .await
        .unwrap();

    // Event 3
    store
        .append(EventInput::new(
            "trace-1",
            Source::Client,
            Category::File,
            "file.transfer",
            Actor::new("user-admin"),
            Outcome::Success,
            json!({"bytes": 2048}),
        ))
        .await
        .unwrap();

    // Event 4
    store
        .append(EventInput::new(
            "trace-1",
            Source::Api,
            Category::Alarm,
            "alarm.rate_limit",
            Actor::new("system"),
            Outcome::Failure,
            json!({"attempts": 35}),
        ))
        .await
        .unwrap();

    // Event 5
    store
        .append(EventInput::new(
            "trace-1",
            Source::Console,
            Category::Console,
            "console.user_update",
            Actor::new("user-admin"),
            Outcome::Success,
            json!({"target": "operator-1"}),
        ))
        .await
        .unwrap();

    // Checkpoint 2 (covers events 1..5)
    store
        .create_checkpoint(&signing_key, "key-audit-2026")
        .await
        .unwrap();

    (
        dir,
        db_path.to_str().unwrap().to_string(),
        signing_key,
        pubkey_hex,
    )
}

#[tokio::test]
async fn test_cli_verify_valid_file() {
    let (dir, db_path, _sk, pubkey_hex) = setup_test_audit_db().await;
    let jsonl_path = dir.path().join("exported_audit.jsonl");
    let bin = get_bin_path();

    // 1. Export DB to JSONL
    let export_status = Command::new(&bin)
        .args(["export-db", &db_path, jsonl_path.to_str().unwrap()])
        .status()
        .expect("run export-db");

    assert!(export_status.success(), "export-db must exit 0");
    assert!(jsonl_path.exists(), "jsonl file must be created");

    // 2. Verify with pubkey file
    let pubkey_path = dir.path().join("audit.pub");
    let verify_output = Command::new(&bin)
        .args([
            "verify",
            jsonl_path.to_str().unwrap(),
            "--pubkey",
            pubkey_path.to_str().unwrap(),
            "--verbose",
        ])
        .output()
        .expect("run verify with pubkey file");

    let stdout = String::from_utf8_lossy(&verify_output.stdout);
    assert!(
        verify_output.status.success(),
        "verify must exit 0 on valid file. Output:\n{}",
        stdout
    );
    assert!(stdout.contains("Status:             VALID"));
    assert!(stdout.contains("Total Events:       5"));
    assert!(stdout.contains("Total Checkpoints:  2"));
    assert!(stdout.contains("Verified Range:     [1..5]"));
    assert!(stdout.contains("Signatures:         VERIFIED (Ed25519)"));

    // 3. Verify with pubkey hex string argument directly
    let verify_hex_output = Command::new(&bin)
        .args([
            "verify",
            jsonl_path.to_str().unwrap(),
            "--pubkey",
            &pubkey_hex,
        ])
        .output()
        .expect("run verify with pubkey hex");

    assert!(verify_hex_output.status.success());
    let stdout_hex = String::from_utf8_lossy(&verify_hex_output.stdout);
    assert!(stdout_hex.contains("Status:             VALID"));
}

#[tokio::test]
async fn test_cli_verify_modified_line_fails_with_exact_sequence() {
    let (dir, db_path, _sk, _pubkey_hex) = setup_test_audit_db().await;
    let jsonl_path = dir.path().join("exported_audit.jsonl");
    let bin = get_bin_path();

    // Export DB
    Command::new(&bin)
        .args(["export-db", &db_path, jsonl_path.to_str().unwrap()])
        .status()
        .unwrap();

    let content = fs::read_to_string(&jsonl_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();

    // Find and modify event sequence 3
    let mut tampered_lines = Vec::new();
    for line in lines {
        if line.contains(r#""sequence":3"#) && line.contains(r#""action":"file.transfer""#) {
            // Tamper with action or details
            let tampered = line.replace("file.transfer", "file.malicious_tamper");
            tampered_lines.push(tampered);
        } else {
            tampered_lines.push(line.to_string());
        }
    }

    let tampered_path = dir.path().join("tampered_audit.jsonl");
    fs::write(&tampered_path, tampered_lines.join("\n")).unwrap();

    let verify_output = Command::new(&bin)
        .args(["verify", tampered_path.to_str().unwrap()])
        .output()
        .expect("run verify");

    assert!(
        !verify_output.status.success(),
        "verify must exit 1 when event is modified"
    );
    let stdout = String::from_utf8_lossy(&verify_output.stdout);
    assert!(stdout.contains("Status:             CORRUPTED"));
    assert!(
        stdout.contains("Failed Sequence:    3"),
        "Must identify sequence 3 as failure point. Output:\n{}",
        stdout
    );
    assert!(stdout.contains("Hash mismatch at sequence 3"));
}

#[tokio::test]
async fn test_cli_verify_deleted_line_fails_with_sequence_gap() {
    let (dir, db_path, _sk, _pubkey_hex) = setup_test_audit_db().await;
    let jsonl_path = dir.path().join("exported_audit.jsonl");
    let bin = get_bin_path();

    // Export DB
    Command::new(&bin)
        .args(["export-db", &db_path, jsonl_path.to_str().unwrap()])
        .status()
        .unwrap();

    let content = fs::read_to_string(&jsonl_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();

    // Delete event sequence 4 (between event 3 and event 5)
    let mut modified_lines = Vec::new();
    for line in lines {
        if line.contains(r#""sequence":4"#) && line.contains(r#""action":"alarm.rate_limit""#) {
            // Skip sequence 4
            continue;
        }
        modified_lines.push(line);
    }

    let gap_path = dir.path().join("gap_audit.jsonl");
    fs::write(&gap_path, modified_lines.join("\n")).unwrap();

    let verify_output = Command::new(&bin)
        .args(["verify", gap_path.to_str().unwrap()])
        .output()
        .expect("run verify");

    assert!(
        !verify_output.status.success(),
        "verify must exit 1 when event line is deleted"
    );
    let stdout = String::from_utf8_lossy(&verify_output.stdout);
    assert!(stdout.contains("Status:             CORRUPTED"));
    assert!(
        stdout.contains("Sequence gap detected: expected 4, found 5"),
        "Must detect sequence gap. Output:\n{}",
        stdout
    );
}

#[tokio::test]
async fn test_cli_verify_forged_checkpoint_signature() {
    let (dir, db_path, _sk, pubkey_hex) = setup_test_audit_db().await;
    let jsonl_path = dir.path().join("exported_audit.jsonl");
    let bin = get_bin_path();

    // Export DB
    Command::new(&bin)
        .args(["export-db", &db_path, jsonl_path.to_str().unwrap()])
        .status()
        .unwrap();

    let content = fs::read_to_string(&jsonl_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();

    // Find checkpoint and tamper signature
    let forged_signature = "0".repeat(128);
    let mut modified_lines = Vec::new();
    for line in lines {
        if line.contains(r#""type":"checkpoint""#) {
            // Replace signature with zeroes
            let mut val: serde_json::Value = serde_json::from_str(line).unwrap();
            val["signature"] = serde_json::Value::String(forged_signature.clone());
            modified_lines.push(serde_json::to_string(&val).unwrap());
        } else {
            modified_lines.push(line.to_string());
        }
    }

    let forged_path = dir.path().join("forged_sig_audit.jsonl");
    fs::write(&forged_path, modified_lines.join("\n")).unwrap();

    let verify_output = Command::new(&bin)
        .args([
            "verify",
            forged_path.to_str().unwrap(),
            "--pubkey",
            &pubkey_hex,
        ])
        .output()
        .expect("run verify");

    assert!(
        !verify_output.status.success(),
        "verify must exit 1 when checkpoint signature is forged"
    );
    let stdout = String::from_utf8_lossy(&verify_output.stdout);
    assert!(stdout.contains("Status:             CORRUPTED"));
    assert!(
        stdout.contains("signature verification failed"),
        "Must indicate signature verification failure. Output:\n{}",
        stdout
    );
}
