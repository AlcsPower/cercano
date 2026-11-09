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
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{compute_file_sha256, BaseBinaryInfo, BuildArtifact, BuildError, BuildOptions};

pub const DEFAULT_SBOM_CDX_NAME: &str = "cercano-sbom.cdx.json";
pub const DEFAULT_SBOM_SPDX_NAME: &str = "cercano-sbom.spdx.json";
pub const DEFAULT_PROVENANCE_NAME: &str = "build-provenance.json";

/// Formato estándar soportado para la generación del Software Bill of Materials (SBOM).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum, Default)]
#[serde(rename_all = "lowercase")]
pub enum SbomFormat {
    #[default]
    #[value(name = "cyclonedx", alias = "cdx")]
    CycloneDx,
    #[value(name = "spdx")]
    Spdx,
}

impl SbomFormat {
    pub fn default_filename(&self) -> &'static str {
        match self {
            Self::CycloneDx => DEFAULT_SBOM_CDX_NAME,
            Self::Spdx => DEFAULT_SBOM_SPDX_NAME,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CycloneDx => "cyclonedx",
            Self::Spdx => "spdx",
        }
    }
}

// ---------------------------------------------------------------------------
// Modelos CycloneDX (JSON v1.5 standard)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxBom {
    pub bom_format: String,
    pub spec_version: String,
    pub serial_number: String,
    pub version: u32,
    pub metadata: CycloneDxMetadata,
    pub components: Vec<CycloneDxComponent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_references: Option<Vec<CycloneDxExternalReference>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxMetadata {
    pub timestamp: String,
    pub tools: Vec<CycloneDxTool>,
    pub authors: Vec<CycloneDxAuthor>,
    pub component: CycloneDxComponent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxTool {
    pub vendor: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxAuthor {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxComponent {
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub licenses: Option<Vec<CycloneDxLicenseChoice>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<Vec<CycloneDxHash>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxLicenseChoice {
    pub license: CycloneDxLicense,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxLicense {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxHash {
    pub alg: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxExternalReference {
    #[serde(rename = "type")]
    pub ref_type: String,
    pub url: String,
}

// ---------------------------------------------------------------------------
// Modelos SPDX (JSON v2.3 standard)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SpdxDocument {
    pub spdx_version: String,
    pub data_license: String,
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    pub name: String,
    pub document_namespace: String,
    pub creation_info: SpdxCreationInfo,
    pub packages: Vec<SpdxPackage>,
    pub files: Vec<SpdxFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationships: Option<Vec<SpdxRelationship>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SpdxCreationInfo {
    pub creators: Vec<String>,
    pub created: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    pub name: String,
    pub version_info: String,
    pub download_location: String,
    pub files_analyzed: bool,
    pub license_concluded: String,
    pub license_declared: String,
    pub supplier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksums: Option<Vec<SpdxChecksum>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SpdxFile {
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    pub file_name: String,
    pub license_concluded: String,
    pub checksums: Vec<SpdxChecksum>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SpdxChecksum {
    pub algorithm: String,
    pub checksum_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SpdxRelationship {
    pub spdx_element_id: String,
    pub relationship_type: String,
    pub related_spdx_element: String,
}

// ---------------------------------------------------------------------------
// Modelos de Atestación de Procedencia (Build Provenance)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildProvenance {
    pub schema_version: String,
    pub build_id: String,
    pub created_at: String,
    pub builder: BuilderProvenanceInfo,
    pub build_parameters: BuildParametersProvenance,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_binary: Option<BaseBinaryInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
    pub materials: Vec<ProvenanceMaterial>,
    pub reproducibility: ReproducibilityMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuilderProvenanceInfo {
    pub name: String,
    pub version: String,
    pub source_revision: String,
    pub target_arch: String,
    pub target_os: String,
    pub rust_channel: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildParametersProvenance {
    pub role: String,
    pub profile_id: String,
    pub strategy: String,
    pub package_windows: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade_code: Option<String>,
    pub authenticode_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_driver: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_url: Option<String>,
    pub sbom_format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceMaterial {
    pub name: String,
    pub uri: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReproducibilityMetadata {
    pub deterministic_timestamp: bool,
    pub environment_isolated: bool,
    pub clean_room_policy: bool,
}

// ---------------------------------------------------------------------------
// Funciones de utilidad y generación
// ---------------------------------------------------------------------------

pub fn get_source_revision() -> String {
    if let Ok(var) = std::env::var("CERCANO_GIT_COMMIT") {
        if !var.trim().is_empty() {
            return var.trim().to_string();
        }
    }
    if let Ok(var) = std::env::var("GIT_COMMIT") {
        if !var.trim().is_empty() {
            return var.trim().to_string();
        }
    }
    "clean-room-f3".to_string()
}

pub fn sanitize_spdx_id(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Contexto con los metadatos requeridos para la generación de SBOM y procedencia.
#[derive(Debug, Clone)]
pub struct SbomContext<'a> {
    pub build_id: &'a str,
    pub profile_id: &'a str,
    pub role: &'a str,
    pub version: &'a str,
    pub app_name: Option<&'a str>,
    pub timestamp: &'a str,
    pub base_binary: Option<&'a BaseBinaryInfo>,
    pub signing_key_id: Option<&'a str>,
}

/// Genera el documento de atestación de procedencia del build.
pub fn generate_provenance(
    ctx: &SbomContext<'_>,
    options: &BuildOptions,
    materials: &[BuildArtifact],
) -> BuildProvenance {
    let provenance_materials: Vec<ProvenanceMaterial> = materials
        .iter()
        .map(|art| ProvenanceMaterial {
            name: art.file_name.clone(),
            uri: format!("artifact://{}", art.file_name),
            sha256: art.sha256.clone(),
            size_bytes: art.size_bytes,
        })
        .collect();

    BuildProvenance {
        schema_version: "1.0.0".to_string(),
        build_id: ctx.build_id.to_string(),
        created_at: ctx.timestamp.to_string(),
        builder: BuilderProvenanceInfo {
            name: "cercano-build".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            source_revision: get_source_revision(),
            target_arch: std::env::consts::ARCH.to_string(),
            target_os: std::env::consts::OS.to_string(),
            rust_channel: "stable".to_string(),
        },
        build_parameters: BuildParametersProvenance {
            role: ctx.role.to_string(),
            profile_id: ctx.profile_id.to_string(),
            strategy: "A".to_string(),
            package_windows: options.package_windows,
            upgrade_code: options.upgrade_code.clone(),
            authenticode_enabled: options.authenticode_enabled,
            signing_driver: options.signing_driver.clone(),
            timestamp_url: options.timestamp_url.clone(),
            sbom_format: options.sbom_format.as_str().to_string(),
        },
        base_binary: ctx.base_binary.cloned(),
        signing_key_id: ctx.signing_key_id.map(ToString::to_string),
        materials: provenance_materials,
        reproducibility: ReproducibilityMetadata {
            deterministic_timestamp: true,
            environment_isolated: true,
            clean_room_policy: true,
        },
    }
}

/// Genera un SBOM CycloneDX (JSON v1.5).
pub fn generate_cyclonedx_sbom(
    build_id: &str,
    role: &str,
    version: &str,
    app_name: Option<&str>,
    artifacts: &[BuildArtifact],
    package_windows: bool,
    timestamp: &str,
) -> CycloneDxBom {
    let root_pkg_name = format!("cercano-{}", role);
    let display_title = app_name.unwrap_or(&root_pkg_name);

    let root_component = CycloneDxComponent {
        component_type: "application".to_string(),
        name: root_pkg_name.clone(),
        version: version.to_string(),
        description: Some(format!("{} (rol {})", display_title, role)),
        licenses: Some(vec![CycloneDxLicenseChoice {
            license: CycloneDxLicense {
                id: "AGPL-3.0-only".to_string(),
            },
        }]),
        hashes: None,
        purl: Some(format!("pkg:generic/{}@{}", root_pkg_name, version)),
    };

    let mut components = Vec::new();

    // Si se empaquetó para Windows, registrar componente de plataforma/sistema operativo
    if package_windows {
        components.push(CycloneDxComponent {
            component_type: "operating-system".to_string(),
            name: "Microsoft Windows".to_string(),
            version: "10/11/Server".to_string(),
            description: Some("Plataforma operativa de destino para el cliente".to_string()),
            licenses: None,
            hashes: None,
            purl: Some("pkg:generic/windows@10-11".to_string()),
        });
    }

    // Registrar cada artefacto como componente (application o file)
    for art in artifacts {
        let comp_type = if art.file_name.ends_with(".exe") || art.file_name.ends_with(".msi") {
            "application"
        } else {
            "file"
        };

        components.push(CycloneDxComponent {
            component_type: comp_type.to_string(),
            name: art.file_name.clone(),
            version: version.to_string(),
            description: Some(format!("Artefacto de compilación {}", art.file_name)),
            licenses: Some(vec![CycloneDxLicenseChoice {
                license: CycloneDxLicense {
                    id: "AGPL-3.0-only".to_string(),
                },
            }]),
            hashes: Some(vec![CycloneDxHash {
                alg: "SHA-256".to_string(),
                content: art.sha256.clone(),
            }]),
            purl: Some(format!("pkg:generic/{}@{}", art.file_name, version)),
        });
    }

    let external_references = vec![CycloneDxExternalReference {
        ref_type: "build-provenance".to_string(),
        url: format!("./{}", DEFAULT_PROVENANCE_NAME),
    }];

    CycloneDxBom {
        bom_format: "CycloneDX".to_string(),
        spec_version: "1.5".to_string(),
        serial_number: format!("urn:uuid:{}", build_id),
        version: 1,
        metadata: CycloneDxMetadata {
            timestamp: timestamp.to_string(),
            tools: vec![CycloneDxTool {
                vendor: "Cercano".to_string(),
                name: "cercano-build".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            }],
            authors: vec![CycloneDxAuthor {
                name: "Cercano Contributors".to_string(),
                email: None,
            }],
            component: root_component,
        },
        components,
        external_references: Some(external_references),
    }
}

/// Genera un SBOM SPDX (JSON v2.3).
pub fn generate_spdx_sbom(
    build_id: &str,
    role: &str,
    version: &str,
    app_name: Option<&str>,
    artifacts: &[BuildArtifact],
    timestamp: &str,
) -> SpdxDocument {
    let root_pkg_name = format!("cercano-{}", role);
    let display_title = app_name.unwrap_or(&root_pkg_name);
    let pkg_spdx_id = format!("SPDXRef-Package-{}", sanitize_spdx_id(&root_pkg_name));

    let main_package = SpdxPackage {
        spdx_id: pkg_spdx_id.clone(),
        name: root_pkg_name.clone(),
        version_info: version.to_string(),
        download_location: "NOASSERTION".to_string(),
        files_analyzed: false,
        license_concluded: "AGPL-3.0-only".to_string(),
        license_declared: "AGPL-3.0-only".to_string(),
        supplier: "Organization: Cercano Contributors".to_string(),
        checksums: None,
        description: Some(format!("{} (rol {})", display_title, role)),
    };

    let mut files = Vec::new();
    let mut relationships = Vec::new();

    // Relación de descripción de documento a paquete principal
    relationships.push(SpdxRelationship {
        spdx_element_id: "SPDXRef-DOCUMENT".to_string(),
        relationship_type: "DESCRIBES".to_string(),
        related_spdx_element: pkg_spdx_id.clone(),
    });

    for art in artifacts {
        let file_spdx_id = format!("SPDXRef-File-{}", sanitize_spdx_id(&art.file_name));
        files.push(SpdxFile {
            spdx_id: file_spdx_id.clone(),
            file_name: format!("./{}", art.file_name),
            license_concluded: "AGPL-3.0-only".to_string(),
            checksums: vec![SpdxChecksum {
                algorithm: "SHA256".to_string(),
                checksum_value: art.sha256.clone(),
            }],
        });

        relationships.push(SpdxRelationship {
            spdx_element_id: pkg_spdx_id.clone(),
            relationship_type: "CONTAINS".to_string(),
            related_spdx_element: file_spdx_id,
        });
    }

    SpdxDocument {
        spdx_version: "SPDX-2.3".to_string(),
        data_license: "CC0-1.0".to_string(),
        spdx_id: "SPDXRef-DOCUMENT".to_string(),
        name: format!("{}-{}", root_pkg_name, version),
        document_namespace: format!("https://cercano.local/spdx/{}/{}", role, build_id),
        creation_info: SpdxCreationInfo {
            creators: vec![
                format!("Tool: cercano-build-{}", env!("CARGO_PKG_VERSION")),
                "Organization: Cercano Contributors".to_string(),
            ],
            created: timestamp.to_string(),
        },
        packages: vec![main_package],
        files,
        relationships: Some(relationships),
    }
}

/// Escribe el archivo de atestación de procedencia `build-provenance.json` y el archivo SBOM
/// (`cercano-sbom.cdx.json` o `cercano-sbom.spdx.json`) en el directorio de destino.
///
/// Retorna `(provenance_artifact, sbom_artifact, provenance_path, sbom_path)`.
pub fn write_sbom_and_provenance(
    target_dir: &Path,
    ctx: &SbomContext<'_>,
    options: &BuildOptions,
    current_artifacts: &[BuildArtifact],
) -> Result<(BuildArtifact, BuildArtifact, PathBuf, PathBuf), BuildError> {
    // 1. Generar y escribir `build-provenance.json`
    let provenance = generate_provenance(ctx, options, current_artifacts);
    let provenance_path = target_dir.join(DEFAULT_PROVENANCE_NAME);
    let provenance_json = serde_json::to_string_pretty(&provenance)?;
    fs::write(&provenance_path, provenance_json.as_bytes()).map_err(|source| BuildError::Io {
        path: provenance_path.clone(),
        source,
    })?;
    let (prov_hash, prov_len) = compute_file_sha256(&provenance_path)?;
    let prov_artifact = BuildArtifact {
        file_name: DEFAULT_PROVENANCE_NAME.to_string(),
        sha256: prov_hash,
        size_bytes: prov_len,
    };

    // 2. Incluir provenance dentro de la lista de artefactos que describe el SBOM
    let mut sbom_artifacts = current_artifacts.to_vec();
    sbom_artifacts.push(prov_artifact.clone());

    // 3. Generar y escribir el SBOM según el formato especificado
    let (sbom_filename, sbom_json) = match options.sbom_format {
        SbomFormat::CycloneDx => {
            let bom = generate_cyclonedx_sbom(
                ctx.build_id,
                ctx.role,
                ctx.version,
                ctx.app_name,
                &sbom_artifacts,
                options.package_windows,
                ctx.timestamp,
            );
            (DEFAULT_SBOM_CDX_NAME, serde_json::to_string_pretty(&bom)?)
        }
        SbomFormat::Spdx => {
            let doc = generate_spdx_sbom(
                ctx.build_id,
                ctx.role,
                ctx.version,
                ctx.app_name,
                &sbom_artifacts,
                ctx.timestamp,
            );
            (DEFAULT_SBOM_SPDX_NAME, serde_json::to_string_pretty(&doc)?)
        }
    };

    let sbom_path = target_dir.join(sbom_filename);
    fs::write(&sbom_path, sbom_json.as_bytes()).map_err(|source| BuildError::Io {
        path: sbom_path.clone(),
        source,
    })?;
    let (sbom_hash, sbom_len) = compute_file_sha256(&sbom_path)?;
    let sbom_artifact = BuildArtifact {
        file_name: sbom_filename.to_string(),
        sha256: sbom_hash,
        size_bytes: sbom_len,
    };

    Ok((prov_artifact, sbom_artifact, provenance_path, sbom_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cyclonedx_generation_schema_validity() {
        let artifacts = vec![
            BuildArtifact {
                file_name: "cercano-profile.signed.json".to_string(),
                sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_string(),
                size_bytes: 1024,
            },
            BuildArtifact {
                file_name: "cercano.exe".to_string(),
                sha256: "1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
                size_bytes: 5242880,
            },
        ];

        let bom = generate_cyclonedx_sbom(
            "test-build-123",
            "soporte",
            "1.0.0",
            Some("Cercano Soporte"),
            &artifacts,
            true,
            "2026-11-09T12:00:00Z",
        );

        assert_eq!(bom.bom_format, "CycloneDX");
        assert_eq!(bom.spec_version, "1.5");
        assert_eq!(bom.serial_number, "urn:uuid:test-build-123");
        assert_eq!(bom.metadata.component.name, "cercano-soporte");
        assert!(bom
            .metadata
            .component
            .description
            .as_ref()
            .unwrap()
            .contains("Cercano Soporte"));
        assert_eq!(
            bom.metadata.component.licenses.as_ref().unwrap()[0]
                .license
                .id,
            "AGPL-3.0-only"
        );

        // Debería tener el OS component + 2 artefactos = 3 componentes
        assert_eq!(bom.components.len(), 3);
        let os_comp = bom
            .components
            .iter()
            .find(|c| c.component_type == "operating-system");
        assert!(os_comp.is_some());
        assert_eq!(os_comp.unwrap().name, "Microsoft Windows");

        let bin_comp = bom
            .components
            .iter()
            .find(|c| c.name == "cercano.exe")
            .unwrap();
        assert_eq!(bin_comp.component_type, "application");
        assert_eq!(bin_comp.hashes.as_ref().unwrap()[0].alg, "SHA-256");

        // Validar serialización JSON de ida y vuelta
        let json_str = serde_json::to_string_pretty(&bom).unwrap();
        let deserialized: CycloneDxBom = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized, bom);
    }

    #[test]
    fn test_spdx_generation_schema_validity() {
        let artifacts = vec![BuildArtifact {
            file_name: "cercano-profile.signed.json".to_string(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            size_bytes: 1024,
        }];

        let spdx = generate_spdx_sbom(
            "test-build-456",
            "tecnico",
            "1.0.0",
            None,
            &artifacts,
            "2026-11-09T12:00:00Z",
        );

        assert_eq!(spdx.spdx_version, "SPDX-2.3");
        assert_eq!(spdx.data_license, "CC0-1.0");
        assert_eq!(spdx.spdx_id, "SPDXRef-DOCUMENT");
        assert_eq!(spdx.packages.len(), 1);
        assert_eq!(spdx.packages[0].name, "cercano-tecnico");
        assert_eq!(spdx.packages[0].license_concluded, "AGPL-3.0-only");
        assert_eq!(spdx.files.len(), 1);
        assert_eq!(spdx.files[0].checksums[0].algorithm, "SHA256");

        let json_str = serde_json::to_string_pretty(&spdx).unwrap();
        let deserialized: SpdxDocument = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized, spdx);
    }

    #[test]
    fn test_provenance_generation() {
        let options = BuildOptions::new(PathBuf::from("profile.json"), PathBuf::from("dist"));
        let artifacts = vec![BuildArtifact {
            file_name: "cercano.exe".to_string(),
            sha256: "aaaa".to_string(),
            size_bytes: 100,
        }];

        let ctx = SbomContext {
            build_id: "build-id-789",
            profile_id: "profile-uuid",
            role: "soporte",
            version: "1.0.0",
            app_name: None,
            timestamp: "2026-11-09T12:00:00Z",
            base_binary: None,
            signing_key_id: Some("cercano-dev-key"),
        };

        let prov = generate_provenance(&ctx, &options, &artifacts);

        assert_eq!(prov.schema_version, "1.0.0");
        assert_eq!(prov.build_id, "build-id-789");
        assert_eq!(prov.builder.name, "cercano-build");
        assert_eq!(prov.signing_key_id.as_deref(), Some("cercano-dev-key"));
        assert_eq!(prov.materials.len(), 1);
        assert_eq!(prov.materials[0].name, "cercano.exe");
        assert!(prov.reproducibility.clean_room_policy);

        let json_str = serde_json::to_string_pretty(&prov).unwrap();
        let deserialized: BuildProvenance = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized, prov);
    }
}
