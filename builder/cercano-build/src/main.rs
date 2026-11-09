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

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use cercano_build::{execute_build, BuildOptions};

/// CLI de compilación y empaquetado de clientes especializados Cercano.
#[derive(Parser, Debug)]
#[command(
    name = "cercano-build",
    about = "CLI para empaquetar clientes Cercano especializados por rol (F3-04)",
    version
)]
struct Args {
    /// Ruta al perfil JSON (soporta perfil sin firmar o ya firmado)
    #[arg(short = 'p', long = "profile")]
    profile: PathBuf,

    /// Directorio de salida
    #[arg(short = 'o', long = "out", default_value = "dist/builds")]
    out: PathBuf,

    /// Ruta a clave privada Ed25519 (opcional, para firmar perfil si es raw JSON)
    #[arg(short = 'k', long = "signing-key")]
    signing_key: Option<PathBuf>,

    /// Identificador de clave (opcional)
    #[arg(long = "key-id")]
    key_id: Option<String>,

    /// Ruta al binario base reproducible (opcional; si existe lo empaqueta)
    #[arg(short = 'b', long = "base-binary")]
    base_binary: Option<PathBuf>,

    /// Valida el perfil y sus invariantes de rol (soporte vs tecnico) sin generar artefactos
    #[arg(long = "dry-run")]
    dry_run: bool,

    /// Genera paquetes de instalación de Windows (.exe y .msi) para el rol del perfil (F3-05)
    #[arg(long = "package-windows", alias = "windows", short = 'w')]
    package_windows: bool,

    /// UpgradeCode GUID personalizado para el instalador MSI de Windows (opcional)
    #[arg(long = "upgrade-code")]
    upgrade_code: Option<String>,

    /// Habilita la firma digital Authenticode de artefactos de Windows (.exe y .msi) (F3-06)
    #[arg(long = "sign-authenticode")]
    sign_authenticode: bool,

    /// Driver de firma: "mock", "signtool", o "osslsigncode" (opcional)
    #[arg(long = "signing-driver")]
    signing_driver: Option<String>,

    /// URL del servidor de sellado de tiempo RFC 3161 (obligatorio si la firma está habilitada)
    #[arg(long = "timestamp-url")]
    timestamp_url: Option<String>,

    /// Ruta al certificado / archivo PKCS#12 (.pfx/.p12) (o usar CERCANO_SIGNING_CERT_PATH)
    #[arg(long = "cert-path")]
    cert_path: Option<PathBuf>,

    /// Contraseña del certificado PKCS#12 (o usar CERCANO_SIGNING_CERT_PASS)
    #[arg(long = "cert-pass")]
    cert_pass: Option<String>,

    /// Genera SBOM (Software Bill of Materials) y atestación de procedencia (activo por defecto)
    #[arg(long = "sbom", default_value_t = true, overrides_with = "no_sbom")]
    sbom: bool,

    /// Desactiva la generación de SBOM y atestación de procedencia
    #[arg(long = "no-sbom", action = clap::ArgAction::SetTrue)]
    no_sbom: bool,

    /// Formato del SBOM generado: "cyclonedx" o "spdx"
    #[arg(long = "sbom-format", value_enum, default_value = "cyclonedx")]
    sbom_format: cercano_build::SbomFormat,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let generate_sbom = if args.no_sbom { false } else { args.sbom };

    let options = BuildOptions {
        profile_path: args.profile,
        out_dir: args.out,
        signing_key_path: args.signing_key,
        key_id: args.key_id,
        base_binary_path: args.base_binary,
        dry_run: args.dry_run,
        package_windows: args.package_windows,
        upgrade_code: args.upgrade_code,
        authenticode_enabled: args.sign_authenticode,
        signing_driver: args.signing_driver,
        timestamp_url: args.timestamp_url,
        cert_path: args.cert_path,
        cert_pass: args.cert_pass,
        generate_sbom,
        sbom_format: args.sbom_format,
    };

    match execute_build(&options) {
        Ok(None) => {
            println!("OK: Perfil validado correctamente. Invariantes de rol y esquema conformes.");
            ExitCode::SUCCESS
        }
        Ok(Some(result)) => {
            println!(
                "OK: Artefacto para rol '{}' (versión {}) generado exitosamente en {} ({} ms)",
                result.role,
                result.version,
                result.target_dir.display(),
                result.elapsed_ms
            );
            println!(
                "  - Perfil firmado: {}",
                result.signed_profile_path.display()
            );
            println!("  - Manifiesto:     {}", result.manifest_path.display());
            println!("  - Checksums:      {}", result.checksums_path.display());
            if let Some(ref sbom) = result.sbom_path {
                println!("  - SBOM:           {}", sbom.display());
            }
            if let Some(ref prov) = result.provenance_path {
                println!("  - Procedencia:    {}", prov.display());
            }
            if let Some(ref bin) = result.base_binary_path {
                println!("  - Binario base:   {}", bin.display());
            }
            if let Some(ref exe) = result.windows_exe_path {
                println!("  - Instalador EXE: {}", exe.display());
            }
            if let Some(ref msi) = result.windows_msi_path {
                println!("  - Instalador MSI: {}", msi.display());
            }
            if options.authenticode_enabled {
                println!("  - Authenticode:   Firmado y verificado con sello RFC 3161");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("ERROR: {}", err);
            ExitCode::FAILURE
        }
    }
}
