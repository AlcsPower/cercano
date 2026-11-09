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

use std::fs;
use std::process::Command;
use std::time::Instant;

use cercano_api::profile::SignedCercanoProfile;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn get_bin_path() -> String {
    env!("CARGO_BIN_EXE_cercano-build").to_string()
}

fn compute_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[test]
fn test_dry_run_valid_soporte() {
    let bin = get_bin_path();
    let profile = "../../docs/specs/examples/profile-soporte-valido.json";

    let output = Command::new(&bin)
        .args(["--dry-run", "-p", profile])
        .output()
        .expect("failed to execute cercano-build");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Expected success, got stderr: {}",
        stderr
    );
    assert!(
        stdout.contains("OK: Perfil validado correctamente"),
        "stdout was: {}",
        stdout
    );
}

#[test]
fn test_dry_run_valid_tecnico() {
    let bin = get_bin_path();
    let profile = "../../docs/specs/examples/profile-tecnico-valido.json";

    let output = Command::new(&bin)
        .args(["--dry-run", "-p", profile])
        .output()
        .expect("failed to execute cercano-build");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Expected success, got stderr: {}",
        stderr
    );
    assert!(
        stdout.contains("OK: Perfil validado correctamente"),
        "stdout was: {}",
        stdout
    );
}

#[test]
fn test_dry_run_invalid_soporte_with_outgoing() {
    let bin = get_bin_path();
    let profile = "../../docs/specs/examples/profile-soporte-invalido-capacidades-tecnico.json";

    let output = Command::new(&bin)
        .args(["--dry-run", "-p", profile])
        .output()
        .expect("failed to execute cercano-build");

    assert!(
        !output.status.success(),
        "Expected failure for soporte with outgoing capability"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("allow_outgoing debe ser falso") || stderr.contains("Soporte"),
        "stderr was: {}",
        stderr
    );
}

#[test]
fn test_dry_run_invalid_unknown_fields() {
    let bin = get_bin_path();
    let profile = "../../docs/specs/examples/profile-invalido-campos-desconocidos.json";

    let output = Command::new(&bin)
        .args(["--dry-run", "-p", profile])
        .output()
        .expect("failed to execute cercano-build");

    assert!(
        !output.status.success(),
        "Expected failure for profile with unknown fields"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown field") || stderr.contains("desconocidos"),
        "stderr was: {}",
        stderr
    );
}

#[test]
fn test_dry_run_invalid_tecnico_with_unattended_access() {
    let bin = get_bin_path();
    let dir = tempdir().expect("create tempdir");
    let bad_tecnico_path = dir.path().join("bad-tecnico.json");

    let json_content = r#"{
  "schema_version": "1.0.0",
  "profile_id": "0192e300-2222-7222-8222-000000000002",
  "created_at": "2026-11-09T10:00:00.000Z",
  "role": "tecnico",
  "server": {
    "rendezvous_server": "cercano.lan:21116",
    "relay_server": "relay.lan:21117",
    "api_server": "https://cercano.lan:21114",
    "server_public_key": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
  },
  "policy": {
    "allow_incoming": false,
    "allow_outgoing": true,
    "unattended_access": true,
    "require_approval": false,
    "hide_network_settings": true
  },
  "installation": {
    "mode": "portable",
    "auto_start": false,
    "create_desktop_shortcut": false,
    "silent": true
  }
}"#;
    fs::write(&bad_tecnico_path, json_content).expect("write bad json");

    let output = Command::new(&bin)
        .args(["--dry-run", "-p", bad_tecnico_path.to_str().unwrap()])
        .output()
        .expect("failed to execute cercano-build");

    assert!(
        !output.status.success(),
        "Expected failure for tecnico with unattended_access"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unattended_access no está permitido") || stderr.contains("Técnico"),
        "stderr was: {}",
        stderr
    );
}

#[test]
fn test_dry_run_invalid_tecnico_without_outgoing() {
    let bin = get_bin_path();
    let dir = tempdir().expect("create tempdir");
    let bad_tecnico_path = dir.path().join("bad-tecnico-no-out.json");

    let json_content = r#"{
  "schema_version": "1.0.0",
  "profile_id": "0192e300-2222-7222-8222-000000000002",
  "created_at": "2026-11-09T10:00:00.000Z",
  "role": "tecnico",
  "server": {
    "rendezvous_server": "cercano.lan:21116",
    "relay_server": "relay.lan:21117",
    "api_server": "https://cercano.lan:21114",
    "server_public_key": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
  },
  "policy": {
    "allow_incoming": false,
    "allow_outgoing": false,
    "unattended_access": false,
    "require_approval": false,
    "hide_network_settings": true
  },
  "installation": {
    "mode": "portable",
    "auto_start": false,
    "create_desktop_shortcut": false,
    "silent": true
  }
}"#;
    fs::write(&bad_tecnico_path, json_content).expect("write bad json");

    let output = Command::new(&bin)
        .args(["--dry-run", "-p", bad_tecnico_path.to_str().unwrap()])
        .output()
        .expect("failed to execute cercano-build");

    assert!(
        !output.status.success(),
        "Expected failure for tecnico with allow_outgoing=false"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("allow_outgoing debe ser verdadero") || stderr.contains("Técnico"),
        "stderr was: {}",
        stderr
    );
}

#[test]
fn test_build_soporte_strategy_a_under_30s() {
    let bin = get_bin_path();
    let dir = tempdir().expect("create tempdir");
    let out_dir = dir.path().join("dist/builds");
    let profile = "../../docs/specs/examples/profile-soporte-valido.json";

    // Create a mock reproducible base binary
    let base_bin_path = dir.path().join("cercano.exe");
    let base_bin_bytes = b"MOCK_BASE_BINARY_REPRODUCIBLE_V1";
    fs::write(&base_bin_path, base_bin_bytes).expect("write mock base binary");

    let start = Instant::now();
    let output = Command::new(&bin)
        .args([
            "-p",
            profile,
            "-o",
            out_dir.to_str().unwrap(),
            "-b",
            base_bin_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute cercano-build");
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 30,
        "Build took {:?}, must be under 30 s",
        elapsed
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "Build failed. stderr: {}, stdout: {}",
        stderr,
        stdout
    );

    // Verify bundle folder
    let bundle_dir = out_dir.join("cercano-soporte-1.0.0");
    assert!(
        bundle_dir.is_dir(),
        "Bundle directory {} does not exist",
        bundle_dir.display()
    );

    // Verify packaged base binary
    let packaged_bin = bundle_dir.join("cercano.exe");
    assert!(packaged_bin.is_file());
    assert_eq!(
        fs::read(&packaged_bin).unwrap(),
        base_bin_bytes,
        "Base binary content mismatch"
    );

    // Verify signed profile
    let signed_profile_file = bundle_dir.join("cercano-profile.signed.json");
    assert!(signed_profile_file.is_file());
    let signed_content = fs::read_to_string(&signed_profile_file).unwrap();
    let signed_env =
        SignedCercanoProfile::from_json_str(&signed_content).expect("Valid signed envelope JSON");

    // Verify signature with default dev key
    let default_dev_key = SigningKey::from_bytes(&[42u8; 32]);
    let verify_res = signed_env.verify(&default_dev_key.verifying_key(), None);
    assert!(
        verify_res.is_ok(),
        "Signature verification failed: {:?}",
        verify_res
    );

    // Verify build manifest
    let manifest_file = bundle_dir.join("build-manifest.json");
    assert!(manifest_file.is_file());
    let manifest_content = fs::read_to_string(&manifest_file).unwrap();
    let manifest_val: serde_json::Value =
        serde_json::from_str(&manifest_content).expect("Valid manifest JSON");
    assert_eq!(manifest_val["role"], "soporte");
    assert_eq!(manifest_val["version"], "1.0.0");
    assert_eq!(manifest_val["strategy"], "A");
    assert_eq!(manifest_val["base_binary"]["file_name"], "cercano.exe");

    // Verify SHA256SUMS
    let checksums_file = bundle_dir.join("SHA256SUMS");
    assert!(checksums_file.is_file());
    let checksums_content = fs::read_to_string(&checksums_file).unwrap();

    let lines: Vec<&str> = checksums_content.lines().collect();
    assert_eq!(lines.len(), 3, "Expected 3 entries in SHA256SUMS");

    for line in lines {
        let parts: Vec<&str> = line.split("  ").collect();
        assert_eq!(parts.len(), 2);
        let hash = parts[0];
        let file_name = parts[1];
        let target_file = bundle_dir.join(file_name);
        assert!(target_file.is_file(), "File {} does not exist", file_name);
        let actual_hash = compute_sha256(&fs::read(target_file).unwrap());
        assert_eq!(
            hash, actual_hash,
            "Checksum mismatch for file {}",
            file_name
        );
    }
}

#[test]
fn test_build_tecnico_strategy_a_without_base_binary() {
    let bin = get_bin_path();
    let dir = tempdir().expect("create tempdir");
    let out_dir = dir.path().join("dist/builds");
    let profile = "../../docs/specs/examples/profile-tecnico-valido.json";

    let start = Instant::now();
    let output = Command::new(&bin)
        .args(["-p", profile, "-o", out_dir.to_str().unwrap()])
        .output()
        .expect("failed to execute cercano-build");
    let elapsed = start.elapsed();

    assert!(elapsed.as_secs() < 30);
    assert!(output.status.success());

    let bundle_dir = out_dir.join("cercano-tecnico-1.0.0");
    assert!(bundle_dir.is_dir());

    let signed_profile_file = bundle_dir.join("cercano-profile.signed.json");
    assert!(signed_profile_file.is_file());

    let manifest_file = bundle_dir.join("build-manifest.json");
    assert!(manifest_file.is_file());
    let manifest_val: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_file).unwrap()).unwrap();
    assert_eq!(manifest_val["role"], "tecnico");
    assert_eq!(manifest_val["version"], "1.0.0");
    assert!(manifest_val["base_binary"].is_null());

    let checksums_file = bundle_dir.join("SHA256SUMS");
    assert!(checksums_file.is_file());
}

#[test]
fn test_build_with_custom_signing_key_and_key_id() {
    let bin = get_bin_path();
    let dir = tempdir().expect("create tempdir");
    let out_dir = dir.path().join("dist/builds");
    let profile = "../../docs/specs/examples/profile-soporte-valido.json";

    // Generate custom 32-byte key
    let custom_key_bytes = [77u8; 32];
    let custom_signing_key = SigningKey::from_bytes(&custom_key_bytes);
    let key_file = dir.path().join("custom.key");
    fs::write(&key_file, hex::encode(custom_key_bytes)).unwrap();

    let output = Command::new(&bin)
        .args([
            "-p",
            profile,
            "-o",
            out_dir.to_str().unwrap(),
            "-k",
            key_file.to_str().unwrap(),
            "--key-id",
            "prod-key-soporte-01",
        ])
        .output()
        .expect("failed to execute cercano-build");

    assert!(output.status.success());

    let bundle_dir = out_dir.join("cercano-soporte-1.0.0");
    let signed_file = bundle_dir.join("cercano-profile.signed.json");
    let signed_content = fs::read_to_string(&signed_file).unwrap();
    let signed_env = SignedCercanoProfile::from_json_str(&signed_content).unwrap();

    assert_eq!(signed_env.key_id.as_deref(), Some("prod-key-soporte-01"));

    // Verifies with custom key
    let verify_res = signed_env.verify(&custom_signing_key.verifying_key(), None);
    assert!(verify_res.is_ok());

    // Fails with default dev key
    let default_dev_key = SigningKey::from_bytes(&[42u8; 32]);
    let wrong_verify = signed_env.verify(&default_dev_key.verifying_key(), None);
    assert!(wrong_verify.is_err());
}

#[test]
fn test_build_with_already_signed_profile_preserves_signature() {
    let bin = get_bin_path();
    let dir = tempdir().expect("create tempdir");
    let out_dir = dir.path().join("dist/builds");
    let profile_raw = "../../docs/specs/examples/profile-soporte-valido.json";

    // 1. Build first to produce a signed profile
    let step1_out = dir.path().join("step1");
    let out1 = Command::new(&bin)
        .args([
            "-p",
            profile_raw,
            "-o",
            step1_out.to_str().unwrap(),
            "--key-id",
            "existing-signed-key-id",
        ])
        .output()
        .expect("step 1 failed");
    assert!(out1.status.success());

    let signed_profile_path = step1_out
        .join("cercano-soporte-1.0.0")
        .join("cercano-profile.signed.json");
    let signed_content_orig = fs::read_to_string(&signed_profile_path).unwrap();

    // 2. Feed that already signed profile into cercano-build
    let out2 = Command::new(&bin)
        .args([
            "-p",
            signed_profile_path.to_str().unwrap(),
            "-o",
            out_dir.to_str().unwrap(),
        ])
        .output()
        .expect("step 2 failed");
    assert!(out2.status.success());

    let final_signed_path = out_dir
        .join("cercano-soporte-1.0.0")
        .join("cercano-profile.signed.json");
    let final_signed_content = fs::read_to_string(&final_signed_path).unwrap();

    let orig_env = SignedCercanoProfile::from_json_str(&signed_content_orig).unwrap();
    let final_env = SignedCercanoProfile::from_json_str(&final_signed_content).unwrap();

    assert_eq!(orig_env.signature, final_env.signature);
    assert_eq!(orig_env.key_id, final_env.key_id);
}
