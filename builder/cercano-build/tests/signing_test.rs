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

use cercano_build::signing::{
    CodeSigner, MockSigner, DEFAULT_TIMESTAMP_URL, MOCK_SIG_MAGIC_END, MOCK_SIG_MAGIC_START,
};
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

/// TC-F3-06-01: Firma y verificación exitosa con driver Mock y sello RFC 3161
#[test]
fn test_signing_mock_success_packaging_windows() {
    let bin = get_bin_path();
    let profile = "../../docs/specs/examples/profile-soporte-valido.json";
    let tmp = tempdir().expect("failed to create tempdir");
    let out_dir = tmp.path().join("dist");

    let output = Command::new(&bin)
        .args([
            "-p",
            profile,
            "-o",
            out_dir.to_str().unwrap(),
            "--package-windows",
            "--sign-authenticode",
            "--signing-driver",
            "mock",
            "--timestamp-url",
            DEFAULT_TIMESTAMP_URL,
        ])
        .output()
        .expect("failed to run cercano-build");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Expected success, got stderr: {}\nstdout: {}",
        stderr,
        stdout
    );
    assert!(stdout.contains("Authenticode:   Firmado y verificado con sello RFC 3161"));

    let bundle_dir = out_dir.join("cercano-soporte-1.0.0");
    assert!(bundle_dir.is_dir(), "bundle dir must exist");

    let exe_path = bundle_dir.join("cercano-soporte-1.0.0.exe");
    let msi_path = bundle_dir.join("cercano-soporte-1.0.0.msi");
    let manifest_path = bundle_dir.join("build-manifest.json");
    let checksums_path = bundle_dir.join("SHA256SUMS");

    assert!(exe_path.is_file(), "signed .exe must exist");
    assert!(msi_path.is_file(), "signed .msi must exist");
    assert!(manifest_path.is_file(), "manifest must exist");
    assert!(checksums_path.is_file(), "checksums must exist");

    // Verificar que los archivos contengan los delimitadores de firma Authenticode Mock
    let exe_bytes = fs::read(&exe_path).unwrap();
    let msi_bytes = fs::read(&msi_path).unwrap();

    assert!(
        exe_bytes
            .windows(MOCK_SIG_MAGIC_START.len())
            .any(|w| w == MOCK_SIG_MAGIC_START),
        ".exe must contain signature magic start"
    );
    assert!(
        exe_bytes
            .windows(MOCK_SIG_MAGIC_END.len())
            .any(|w| w == MOCK_SIG_MAGIC_END),
        ".exe must contain signature magic end"
    );

    assert!(
        msi_bytes
            .windows(MOCK_SIG_MAGIC_START.len())
            .any(|w| w == MOCK_SIG_MAGIC_START),
        ".msi must contain signature magic start"
    );
    assert!(
        msi_bytes
            .windows(MOCK_SIG_MAGIC_END.len())
            .any(|w| w == MOCK_SIG_MAGIC_END),
        ".msi must contain signature magic end"
    );

    // Verificar con el verificador CodeSigner
    let verifier = MockSigner::new(DEFAULT_TIMESTAMP_URL.to_string()).unwrap();
    verifier
        .verify(&exe_path)
        .expect("exe verification must succeed");
    verifier
        .verify(&msi_path)
        .expect("msi verification must succeed");

    // Verificar manifiesto de procedencia
    let manifest_content = fs::read_to_string(&manifest_path).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&manifest_content).unwrap();

    assert_eq!(manifest["authenticode"]["driver"], "mock");
    assert_eq!(
        manifest["authenticode"]["timestamp_url"],
        DEFAULT_TIMESTAMP_URL
    );
    assert_eq!(manifest["authenticode"]["verified"], true);

    // Verificar que los hashes en SHA256SUMS corresponden exactamente a los archivos firmados finales
    let sums_content = fs::read_to_string(&checksums_path).unwrap();
    let exe_hash = compute_sha256(&exe_bytes);
    let msi_hash = compute_sha256(&msi_bytes);

    assert!(
        sums_content.contains(&format!("{}  cercano-soporte-1.0.0.exe", exe_hash)),
        "SHA256SUMS must contain exact hash of signed .exe"
    );
    assert!(
        sums_content.contains(&format!("{}  cercano-soporte-1.0.0.msi", msi_hash)),
        "SHA256SUMS must contain exact hash of signed .msi"
    );
}

/// TC-F3-06-02: Rechazo si falta el timestamp RFC 3161 obligatorio
#[test]
fn test_signing_missing_timestamp_rejected() {
    let bin = get_bin_path();
    let profile = "../../docs/specs/examples/profile-soporte-valido.json";
    let tmp = tempdir().expect("failed to create tempdir");
    let out_dir = tmp.path().join("dist");

    // Se especifica --sign-authenticode pero NO se provee --timestamp-url
    let output = Command::new(&bin)
        .args([
            "-p",
            profile,
            "-o",
            out_dir.to_str().unwrap(),
            "--sign-authenticode",
            "--signing-driver",
            "mock",
        ])
        .output()
        .expect("failed to run cercano-build");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "Expected failure when timestamp-url is missing, but succeeded"
    );
    assert!(
        stderr.contains("El sello de tiempo RFC 3161 es obligatorio"),
        "stderr must explain missing RFC 3161 timestamp, got: {}",
        stderr
    );

    // Criterio de aceptación estricto: ningún directorio ni artefacto debe crearse
    assert!(
        !out_dir.exists() || fs::read_dir(&out_dir).unwrap().next().is_none(),
        "No directory or artifacts should exist when build is aborted"
    );
}

/// TC-F3-06-03: Fallo cuando el firmante falla (debe abortar y no publicar artefactos)
#[test]
fn test_signing_failure_aborts_and_cleans_up_no_artifacts() {
    let bin = get_bin_path();
    let profile = "../../docs/specs/examples/profile-soporte-valido.json";
    let tmp = tempdir().expect("failed to create tempdir");
    let out_dir = tmp.path().join("dist");

    let output = Command::new(&bin)
        .env("CERCANO_MOCK_SIGN_FAIL", "1")
        .args([
            "-p",
            profile,
            "-o",
            out_dir.to_str().unwrap(),
            "--package-windows",
            "--sign-authenticode",
            "--signing-driver",
            "mock",
            "--timestamp-url",
            DEFAULT_TIMESTAMP_URL,
        ])
        .output()
        .expect("failed to run cercano-build");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "Process must fail when code signing fails"
    );
    assert!(
        stderr.contains("Fallo al ejecutar el comando de firma")
            || stderr.contains("Fallo simulado en la firma"),
        "stderr must report signing failure, got: {}",
        stderr
    );

    // Criterio de aceptación estricto: NINGÚN artefacto se publica ni queda en el directorio de salida
    let target_dir = out_dir.join("cercano-soporte-1.0.0");
    assert!(
        !target_dir.exists(),
        "Target directory must NOT exist after aborted signing. Artifacts must be completely cleaned up."
    );
}

/// TC-F3-06-04: Fallo cuando la verificación posterior a la firma falla
#[test]
fn test_verification_failure_aborts_and_cleans_up_no_artifacts() {
    let bin = get_bin_path();
    let profile = "../../docs/specs/examples/profile-soporte-valido.json";
    let tmp = tempdir().expect("failed to create tempdir");
    let out_dir = tmp.path().join("dist");

    let output = Command::new(&bin)
        .env("CERCANO_MOCK_VERIFY_FAIL", "1")
        .args([
            "-p",
            profile,
            "-o",
            out_dir.to_str().unwrap(),
            "--package-windows",
            "--sign-authenticode",
            "--signing-driver",
            "mock",
            "--timestamp-url",
            DEFAULT_TIMESTAMP_URL,
        ])
        .output()
        .expect("failed to run cercano-build");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "Process must fail when code verification fails"
    );
    assert!(
        stderr.contains("Fallo en la verificación de firma Authenticode")
            || stderr.contains("Fallo simulado en la verificación"),
        "stderr must report verification failure, got: {}",
        stderr
    );

    // Criterio de aceptación estricto: NINGÚN artefacto se publica ni queda en el directorio de salida
    let target_dir = out_dir.join("cercano-soporte-1.0.0");
    assert!(
        !target_dir.exists(),
        "Target directory must NOT exist after verification failure. Output must be clean."
    );
}

/// TC-F3-06-05: Verificación de firma adulterada (alteración de 1 byte tras la firma causa fallo de verificación)
#[test]
fn test_tampered_artifact_fails_verification() {
    let tmp = tempdir().expect("failed to create tempdir");
    let artifact_path = tmp.path().join("app.exe");
    fs::write(&artifact_path, b"MZ_CERCANO_BINARY_STUB_DATA_1234567890").unwrap();

    let signer = MockSigner::new(DEFAULT_TIMESTAMP_URL.to_string()).unwrap();

    // 1. Firmar artefacto
    signer
        .sign(&artifact_path)
        .expect("initial signing should succeed");

    // 2. Verificar que la firma intacta es válida
    signer
        .verify(&artifact_path)
        .expect("unaltered signature must verify");

    // 3. Adulterar exactamente 1 byte del binario firmado
    let mut data = fs::read(&artifact_path).unwrap();
    data[10] ^= 0x01; // Alterar 1 bit en el byte 10
    fs::write(&artifact_path, &data).unwrap();

    // 4. La verificación debe fallar inequívocamente
    let verify_result = signer.verify(&artifact_path);
    assert!(
        verify_result.is_err(),
        "Verification must fail after tampering 1 byte"
    );

    let err_str = format!("{}", verify_result.unwrap_err());
    assert!(
        err_str.contains("Firma adulterada") || err_str.contains("hash esperado"),
        "Error message must indicate tampering/hash mismatch: {}",
        err_str
    );
}

/// TC-F3-06-06: Firma y verificación con binario base provisto
#[test]
fn test_signing_with_base_binary() {
    let bin = get_bin_path();
    let profile = "../../docs/specs/examples/profile-tecnico-valido.json";
    let tmp = tempdir().expect("failed to create tempdir");
    let out_dir = tmp.path().join("dist");

    let fake_base = tmp.path().join("cercano-base.exe");
    fs::write(
        &fake_base,
        b"MZ_MINIMAL_EXECUTABLE_BASE_BINARY_FOR_TESTS_123456789",
    )
    .unwrap();

    let output = Command::new(&bin)
        .args([
            "-p",
            profile,
            "-o",
            out_dir.to_str().unwrap(),
            "-b",
            fake_base.to_str().unwrap(),
            "--package-windows",
            "--sign-authenticode",
            "--signing-driver",
            "mock",
            "--timestamp-url",
            DEFAULT_TIMESTAMP_URL,
        ])
        .output()
        .expect("failed to run cercano-build");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Expected success with base binary, got stderr: {}\nstdout: {}",
        stderr,
        stdout
    );

    let bundle_dir = out_dir.join("cercano-tecnico-1.0.0");
    let exe_path = bundle_dir.join("cercano-tecnico-1.0.0.exe");
    let msi_path = bundle_dir.join("cercano-tecnico-1.0.0.msi");

    let verifier = MockSigner::new(DEFAULT_TIMESTAMP_URL.to_string()).unwrap();
    verifier
        .verify(&exe_path)
        .expect("tecnico .exe must verify");
    verifier
        .verify(&msi_path)
        .expect("tecnico .msi must verify");
}
