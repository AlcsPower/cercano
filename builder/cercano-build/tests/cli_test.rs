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

#[test]
fn test_windows_packaging_soporte() {
    let bin = get_bin_path();
    let dir = tempdir().expect("create tempdir");
    let out_dir = dir.path().join("dist/builds");
    let profile = "../../docs/specs/examples/profile-soporte-valido.json";

    let start = Instant::now();
    let output = Command::new(&bin)
        .args([
            "-p",
            profile,
            "-o",
            out_dir.to_str().unwrap(),
            "--package-windows",
        ])
        .output()
        .expect("failed to execute cercano-build");
    let elapsed = start.elapsed();

    assert!(elapsed.as_secs() < 30, "Took {:?}, must be < 30s", elapsed);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}, stdout: {}",
        stderr,
        stdout
    );

    let bundle_dir = out_dir.join("cercano-soporte-1.0.0");
    assert!(bundle_dir.is_dir());

    // 1. Validar presencia de artefactos requeridos
    let exe_file = bundle_dir.join("cercano-soporte-1.0.0.exe");
    let msi_file = bundle_dir.join("cercano-soporte-1.0.0.msi");
    let wxs_file = bundle_dir.join("cercano-soporte-1.0.0.wxs");
    let meta_file = bundle_dir.join("installer-metadata.json");
    let signed_profile_file = bundle_dir.join("cercano-profile.signed.json");
    let manifest_file = bundle_dir.join("build-manifest.json");
    let checksums_file = bundle_dir.join("SHA256SUMS");

    assert!(exe_file.is_file(), "EXE installer missing");
    assert!(msi_file.is_file(), "MSI installer missing");
    assert!(wxs_file.is_file(), "WiX source missing");
    assert!(meta_file.is_file(), "Metadata file missing");
    assert!(signed_profile_file.is_file(), "Signed profile missing");
    assert!(manifest_file.is_file(), "Manifest file missing");
    assert!(checksums_file.is_file(), "SHA256SUMS missing");

    // 2. Validar estructura del ejecutable .exe (PE Header + Carga util)
    let exe_bytes = fs::read(&exe_file).unwrap();
    assert!(exe_bytes.len() > 512);
    assert_eq!(&exe_bytes[0..2], b"MZ", "EXE must have PE MZ magic header");

    // 3. Validar estructura del instalador .msi (OLE Compound File Binary Format)
    let msi_bytes = fs::read(&msi_file).unwrap();
    assert!(msi_bytes.len() > 512);
    // Magic de OLE CFBF: D0 CF 11 E0 A1 B1 1A E1
    assert_eq!(
        &msi_bytes[0..8],
        &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
        "MSI must be a valid OLE Compound Document (CFBF)"
    );

    // 4. Validar contenido de build-manifest.json
    let manifest_str = fs::read_to_string(&manifest_file).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&manifest_str).unwrap();

    assert_eq!(manifest["role"], "soporte");
    assert_eq!(manifest["version"], "1.0.0");
    let win_meta = &manifest["windows_metadata"];
    assert!(!win_meta.is_null());
    assert_eq!(win_meta["role"], "soporte");
    assert_eq!(win_meta["display_name"], "Cercano Soporte");
    assert_eq!(
        win_meta["upgrade_code"],
        "C38CA110-5090-4100-B001-000000509001"
    );
    assert_eq!(win_meta["role_isolation"]["opposite_role"], "tecnico");
    assert_eq!(
        win_meta["role_isolation"]["opposite_upgrade_code"],
        "C38CA110-7EC1-4200-B002-0000007EC102"
    );

    // 5. Validar SHA256SUMS cubriendo todos los artefactos generados
    let checksums_str = fs::read_to_string(&checksums_file).unwrap();
    let lines: Vec<&str> = checksums_str.lines().collect();
    assert_eq!(
        lines.len(),
        6,
        "Expected 6 files in bundle (profile, exe, msi, wxs, metadata, manifest)"
    );

    for line in lines {
        let parts: Vec<&str> = line.split("  ").collect();
        assert_eq!(parts.len(), 2);
        let hash = parts[0];
        let file_name = parts[1];
        let fpath = bundle_dir.join(file_name);
        assert!(
            fpath.is_file(),
            "File {} in SHA256SUMS must exist",
            file_name
        );
        let actual_hash = compute_sha256(&fs::read(fpath).unwrap());
        assert_eq!(hash, actual_hash, "Hash mismatch for {}", file_name);
    }
}

#[test]
fn test_windows_packaging_tecnico_with_base_binary() {
    let bin = get_bin_path();
    let dir = tempdir().expect("create tempdir");
    let out_dir = dir.path().join("dist/builds");
    let profile = "../../docs/specs/examples/profile-tecnico-valido.json";

    // Crear binario base simulado
    let base_bin_path = dir.path().join("cercano.exe");
    let base_bin_content = b"MZ\x90\x00_MOCK_BASE_BINARY_PE_TECNICO_";
    fs::write(&base_bin_path, base_bin_content).unwrap();

    let output = Command::new(&bin)
        .args([
            "-p",
            profile,
            "-o",
            out_dir.to_str().unwrap(),
            "-b",
            base_bin_path.to_str().unwrap(),
            "--package-windows",
        ])
        .output()
        .expect("failed to execute cercano-build");

    assert!(output.status.success());

    let bundle_dir = out_dir.join("cercano-tecnico-1.0.0");
    assert!(bundle_dir.is_dir());

    let exe_file = bundle_dir.join("cercano-tecnico-1.0.0.exe");
    let msi_file = bundle_dir.join("cercano-tecnico-1.0.0.msi");
    assert!(exe_file.is_file());
    assert!(msi_file.is_file());

    // Validar aislamiento de roles
    let meta_file = bundle_dir.join("installer-metadata.json");
    let meta: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&meta_file).unwrap()).unwrap();

    assert_eq!(meta["role"], "tecnico");
    assert_eq!(meta["display_name"], "Cercano Técnico");
    assert_eq!(meta["upgrade_code"], "C38CA110-7EC1-4200-B002-0000007EC102");
    assert_eq!(meta["role_isolation"]["opposite_role"], "soporte");
    assert_eq!(
        meta["role_isolation"]["opposite_upgrade_code"],
        "C38CA110-5090-4100-B001-000000509001"
    );
    assert!(meta["role_isolation"]["warning_message"]
        .as_str()
        .unwrap()
        .contains("ADVERTENCIA"));

    // Validar parámetros silenciosos documentados
    let silent_exe = meta["silent_exe_flags"].as_array().unwrap();
    assert!(silent_exe.iter().any(|f| f == "/S"));
    assert!(silent_exe.iter().any(|f| f == "--silent-install"));

    let silent_msi = meta["silent_msi_flags"].as_array().unwrap();
    assert!(silent_msi.iter().any(|f| f == "/quiet"));
    assert!(silent_msi.iter().any(|f| f == "/norestart"));

    // Validar ciclo de vida
    assert_eq!(meta["lifecycle"]["clean_install_supported"], true);
    assert_eq!(meta["lifecycle"]["upgrade_supported"], true);
    assert_eq!(meta["lifecycle"]["clean_uninstall_supported"], true);
}

#[test]
fn test_windows_packaging_custom_upgrade_code() {
    let bin = get_bin_path();
    let dir = tempdir().expect("create tempdir");
    let out_dir = dir.path().join("dist/builds");
    let profile = "../../docs/specs/examples/profile-soporte-valido.json";
    let custom_code = "A1B2C3D4-E5F6-7890-ABCD-EF0123456789";

    let output = Command::new(&bin)
        .args([
            "-p",
            profile,
            "-o",
            out_dir.to_str().unwrap(),
            "--package-windows",
            "--upgrade-code",
            custom_code,
        ])
        .output()
        .expect("failed to execute cercano-build");

    assert!(output.status.success());

    let bundle_dir = out_dir.join("cercano-soporte-1.0.0");
    let meta_file = bundle_dir.join("installer-metadata.json");
    let meta: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&meta_file).unwrap()).unwrap();

    assert_eq!(meta["upgrade_code"], custom_code);
}
