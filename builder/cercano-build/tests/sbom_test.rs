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

use cercano_build::sbom::{
    BuildProvenance, CycloneDxBom, SbomFormat, SpdxDocument, DEFAULT_PROVENANCE_NAME,
    DEFAULT_SBOM_CDX_NAME, DEFAULT_SBOM_SPDX_NAME,
};
use cercano_build::{execute_build, BuildOptions};
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
fn test_cyclonedx_sbom_generation_and_verification() {
    let bin = get_bin_path();
    let dir = tempdir().expect("create tempdir");
    let out_dir = dir.path().join("dist");
    let profile = "../../docs/specs/examples/profile-soporte-valido.json";

    let base_bin_path = dir.path().join("cercano.exe");
    let base_bytes = b"BINARY_CONTENT_FOR_CYCLONEDX_SBOM_TEST";
    fs::write(&base_bin_path, base_bytes).expect("write mock binary");

    let output = Command::new(&bin)
        .args([
            "-p",
            profile,
            "-o",
            out_dir.to_str().unwrap(),
            "-b",
            base_bin_path.to_str().unwrap(),
            "--sbom-format",
            "cyclonedx",
        ])
        .output()
        .expect("execute cercano-build");

    assert!(
        output.status.success(),
        "Build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let bundle_dir = out_dir.join("cercano-soporte-1.0.0");
    let sbom_path = bundle_dir.join(DEFAULT_SBOM_CDX_NAME);
    let prov_path = bundle_dir.join(DEFAULT_PROVENANCE_NAME);
    let checksums_path = bundle_dir.join("SHA256SUMS");
    let manifest_path = bundle_dir.join("build-manifest.json");

    assert!(sbom_path.is_file(), "CycloneDX SBOM file must exist");
    assert!(prov_path.is_file(), "Provenance file must exist");

    // 1. Validar estructura CycloneDX v1.5
    let sbom_content = fs::read_to_string(&sbom_path).expect("read sbom");
    let bom: CycloneDxBom = serde_json::from_str(&sbom_content).expect("parse CycloneDX JSON");

    assert_eq!(bom.bom_format, "CycloneDX");
    assert_eq!(bom.spec_version, "1.5");
    assert!(bom.serial_number.starts_with("urn:uuid:"));
    assert_eq!(bom.version, 1);

    // Metadatos
    assert_eq!(bom.metadata.tools[0].name, "cercano-build");
    assert_eq!(bom.metadata.authors[0].name, "Cercano Contributors");
    assert_eq!(bom.metadata.component.name, "cercano-soporte");
    assert_eq!(
        bom.metadata.component.licenses.as_ref().unwrap()[0]
            .license
            .id,
        "AGPL-3.0-only"
    );

    // Componentes esperados
    let comp_names: Vec<&str> = bom.components.iter().map(|c| c.name.as_str()).collect();
    assert!(comp_names.contains(&"cercano.exe"));
    assert!(comp_names.contains(&"cercano-profile.signed.json"));
    assert!(comp_names.contains(&DEFAULT_PROVENANCE_NAME));

    // Validar hash SHA-256 del binario en el SBOM
    let bin_comp = bom
        .components
        .iter()
        .find(|c| c.name == "cercano.exe")
        .unwrap();
    assert_eq!(bin_comp.component_type, "application");
    assert_eq!(
        bin_comp.licenses.as_ref().unwrap()[0].license.id,
        "AGPL-3.0-only"
    );
    let bin_hash = &bin_comp.hashes.as_ref().unwrap()[0];
    assert_eq!(bin_hash.alg, "SHA-256");
    assert_eq!(bin_hash.content, compute_sha256(base_bytes));

    // Referencia externa a provenance
    let ext_refs = bom.external_references.expect("external references");
    assert!(ext_refs.iter().any(|r| r.ref_type == "build-provenance"));

    // 2. Validar Atestación de procedencia
    let prov_content = fs::read_to_string(&prov_path).expect("read provenance");
    let prov: BuildProvenance = serde_json::from_str(&prov_content).expect("parse provenance JSON");
    assert_eq!(prov.schema_version, "1.0.0");
    assert_eq!(prov.builder.name, "cercano-build");
    assert_eq!(prov.build_parameters.role, "soporte");
    assert_eq!(prov.build_parameters.strategy, "A");
    assert_eq!(prov.build_parameters.sbom_format, "cyclonedx");
    assert!(prov.reproducibility.clean_room_policy);
    assert!(prov.materials.iter().any(|m| m.name == "cercano.exe"));

    // 3. Validar inclusión en build-manifest.json
    let manifest_content = fs::read_to_string(&manifest_path).expect("read manifest");
    let manifest: serde_json::Value = serde_json::from_str(&manifest_content).unwrap();
    let sbom_info = &manifest["sbom"];
    assert_eq!(sbom_info["format"], "cyclonedx");
    assert_eq!(sbom_info["file_name"], DEFAULT_SBOM_CDX_NAME);
    let prov_info = &manifest["provenance"];
    assert_eq!(prov_info["file_name"], DEFAULT_PROVENANCE_NAME);

    // 4. Validar coincidencia exacta en SHA256SUMS
    let checksums_content = fs::read_to_string(&checksums_path).expect("read checksums");
    let actual_sbom_hash = compute_sha256(sbom_content.as_bytes());
    let actual_prov_hash = compute_sha256(prov_content.as_bytes());

    let mut found_sbom = false;
    let mut found_prov = false;

    for line in checksums_content.lines() {
        let parts: Vec<&str> = line.split("  ").collect();
        assert_eq!(parts.len(), 2);
        if parts[1] == DEFAULT_SBOM_CDX_NAME {
            assert_eq!(
                parts[0], actual_sbom_hash,
                "SBOM hash in SHA256SUMS must match"
            );
            found_sbom = true;
        } else if parts[1] == DEFAULT_PROVENANCE_NAME {
            assert_eq!(
                parts[0], actual_prov_hash,
                "Provenance hash in SHA256SUMS must match"
            );
            found_prov = true;
        }
    }

    assert!(found_sbom, "SBOM must be listed in SHA256SUMS");
    assert!(found_prov, "Provenance must be listed in SHA256SUMS");
}

#[test]
fn test_spdx_sbom_generation_and_verification() {
    let bin = get_bin_path();
    let dir = tempdir().expect("create tempdir");
    let out_dir = dir.path().join("dist");
    let profile = "../../docs/specs/examples/profile-tecnico-valido.json";

    let base_bin_path = dir.path().join("cercano-base");
    let base_bytes = b"BINARY_CONTENT_FOR_SPDX_SBOM_TEST";
    fs::write(&base_bin_path, base_bytes).expect("write mock binary");

    let output = Command::new(&bin)
        .args([
            "-p",
            profile,
            "-o",
            out_dir.to_str().unwrap(),
            "-b",
            base_bin_path.to_str().unwrap(),
            "--sbom-format",
            "spdx",
        ])
        .output()
        .expect("execute cercano-build");

    assert!(
        output.status.success(),
        "Build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let bundle_dir = out_dir.join("cercano-tecnico-1.0.0");
    let sbom_path = bundle_dir.join(DEFAULT_SBOM_SPDX_NAME);
    let prov_path = bundle_dir.join(DEFAULT_PROVENANCE_NAME);
    let checksums_path = bundle_dir.join("SHA256SUMS");

    assert!(sbom_path.is_file(), "SPDX SBOM file must exist");
    assert!(prov_path.is_file(), "Provenance file must exist");

    // 1. Validar documento SPDX 2.3
    let sbom_content = fs::read_to_string(&sbom_path).expect("read sbom");
    let spdx: SpdxDocument = serde_json::from_str(&sbom_content).expect("parse SPDX JSON");

    assert_eq!(spdx.spdx_version, "SPDX-2.3");
    assert_eq!(spdx.data_license, "CC0-1.0");
    assert_eq!(spdx.spdx_id, "SPDXRef-DOCUMENT");
    assert!(spdx.name.starts_with("cercano-tecnico"));
    assert_eq!(spdx.packages.len(), 1);
    assert_eq!(spdx.packages[0].name, "cercano-tecnico");
    assert_eq!(spdx.packages[0].license_concluded, "AGPL-3.0-only");
    assert_eq!(spdx.packages[0].license_declared, "AGPL-3.0-only");

    // Archivos registrados en SPDX
    let file_names: Vec<&str> = spdx.files.iter().map(|f| f.file_name.as_str()).collect();
    assert!(file_names.contains(&"./cercano-base"));
    assert!(file_names.contains(&"./cercano-profile.signed.json"));
    assert!(file_names.contains(&format!("./{}", DEFAULT_PROVENANCE_NAME).as_str()));

    let bin_file = spdx
        .files
        .iter()
        .find(|f| f.file_name == "./cercano-base")
        .unwrap();
    assert_eq!(bin_file.license_concluded, "AGPL-3.0-only");
    assert_eq!(bin_file.checksums[0].algorithm, "SHA256");
    assert_eq!(
        bin_file.checksums[0].checksum_value,
        compute_sha256(base_bytes)
    );

    // Relaciones
    let rels = spdx.relationships.expect("relationships");
    assert!(rels.iter().any(|r| r.relationship_type == "DESCRIBES"));
    assert!(rels.iter().any(|r| r.relationship_type == "CONTAINS"));

    // 2. Validar coincidencia en SHA256SUMS
    let checksums_content = fs::read_to_string(&checksums_path).expect("read checksums");
    let actual_sbom_hash = compute_sha256(sbom_content.as_bytes());

    let mut found_spdx = false;
    for line in checksums_content.lines() {
        let parts: Vec<&str> = line.split("  ").collect();
        if parts[1] == DEFAULT_SBOM_SPDX_NAME {
            assert_eq!(
                parts[0], actual_sbom_hash,
                "SPDX hash in SHA256SUMS must match"
            );
            found_spdx = true;
        }
    }
    assert!(found_spdx, "SPDX SBOM must be listed in SHA256SUMS");
}

#[test]
fn test_no_sbom_flag_skips_generation() {
    let bin = get_bin_path();
    let dir = tempdir().expect("create tempdir");
    let out_dir = dir.path().join("dist");
    let profile = "../../docs/specs/examples/profile-soporte-valido.json";

    let output = Command::new(&bin)
        .args(["-p", profile, "-o", out_dir.to_str().unwrap(), "--no-sbom"])
        .output()
        .expect("execute cercano-build");

    assert!(
        output.status.success(),
        "Build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let bundle_dir = out_dir.join("cercano-soporte-1.0.0");
    let sbom_cdx = bundle_dir.join(DEFAULT_SBOM_CDX_NAME);
    let sbom_spdx = bundle_dir.join(DEFAULT_SBOM_SPDX_NAME);
    let prov = bundle_dir.join(DEFAULT_PROVENANCE_NAME);
    let manifest_path = bundle_dir.join("build-manifest.json");
    let checksums_path = bundle_dir.join("SHA256SUMS");

    assert!(
        !sbom_cdx.exists(),
        "CycloneDX SBOM must NOT exist with --no-sbom"
    );
    assert!(
        !sbom_spdx.exists(),
        "SPDX SBOM must NOT exist with --no-sbom"
    );
    assert!(!prov.exists(), "Provenance must NOT exist with --no-sbom");

    let manifest_content = fs::read_to_string(&manifest_path).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&manifest_content).unwrap();
    assert!(manifest.get("sbom").is_none());
    assert!(manifest.get("provenance").is_none());

    let checksums_content = fs::read_to_string(&checksums_path).unwrap();
    assert!(!checksums_content.contains(DEFAULT_SBOM_CDX_NAME));
    assert!(!checksums_content.contains(DEFAULT_SBOM_SPDX_NAME));
    assert!(!checksums_content.contains(DEFAULT_PROVENANCE_NAME));
}

#[test]
fn test_windows_packaging_with_cyclonedx_includes_os_and_installer_artifacts() {
    let bin = get_bin_path();
    let dir = tempdir().expect("create tempdir");
    let out_dir = dir.path().join("dist");
    let profile = "../../docs/specs/examples/profile-soporte-valido.json";

    let output = Command::new(&bin)
        .args([
            "-p",
            profile,
            "-o",
            out_dir.to_str().unwrap(),
            "-w",
            "--sbom-format",
            "cyclonedx",
        ])
        .output()
        .expect("execute cercano-build");

    assert!(
        output.status.success(),
        "Build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let bundle_dir = out_dir.join("cercano-soporte-1.0.0");
    let sbom_path = bundle_dir.join(DEFAULT_SBOM_CDX_NAME);
    let sbom_content = fs::read_to_string(&sbom_path).unwrap();
    let bom: CycloneDxBom = serde_json::from_str(&sbom_content).unwrap();

    let os_comp = bom
        .components
        .iter()
        .find(|c| c.component_type == "operating-system");
    assert!(
        os_comp.is_some(),
        "Must include operating-system component for Windows packaging"
    );

    let exe_comp = bom
        .components
        .iter()
        .find(|c| c.name == "cercano-soporte-1.0.0.exe");
    assert!(
        exe_comp.is_some(),
        "cercano-soporte-1.0.0.exe component must be in SBOM"
    );
    assert_eq!(exe_comp.unwrap().component_type, "application");

    let msi_comp = bom
        .components
        .iter()
        .find(|c| c.name == "cercano-soporte-1.0.0.msi");
    assert!(
        msi_comp.is_some(),
        "cercano-soporte-1.0.0.msi component must be in SBOM"
    );
    assert_eq!(msi_comp.unwrap().component_type, "application");
}

#[test]
fn test_build_options_api_with_spdx_sbom() {
    let dir = tempdir().expect("create tempdir");
    let out_dir = dir.path().join("dist_api");
    let profile = std::path::PathBuf::from("../../docs/specs/examples/profile-tecnico-valido.json");

    let mut opts = BuildOptions::new(profile, out_dir);
    opts.generate_sbom = true;
    opts.sbom_format = SbomFormat::Spdx;

    let res = execute_build(&opts)
        .expect("build should succeed")
        .expect("result");
    assert!(res.sbom_path.is_some());
    assert!(res.provenance_path.is_some());

    let sbom_p = res.sbom_path.unwrap();
    assert!(sbom_p.ends_with(DEFAULT_SBOM_SPDX_NAME));
    assert!(sbom_p.is_file());

    let prov_p = res.provenance_path.unwrap();
    assert!(prov_p.ends_with(DEFAULT_PROVENANCE_NAME));
    assert!(prov_p.is_file());
}
