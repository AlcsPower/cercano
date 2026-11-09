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

use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// URL por defecto para servidores RFC 3161 de sellado de tiempo.
pub const DEFAULT_TIMESTAMP_URL: &str = "http://timestamp.digicert.com";

/// Variable de entorno segura para la ruta al certificado PKCS#12.
pub const ENV_CERT_PATH: &str = "CERCANO_SIGNING_CERT_PATH";

/// Variable de entorno segura para la contraseña del certificado.
pub const ENV_CERT_PASS: &str = "CERCANO_SIGNING_CERT_PASS";

/// Constantes para delimitadores del bloque de firma mock determinista.
pub const MOCK_SIG_MAGIC_START: &[u8] = b"\n--- BEGIN CERCANO AUTHENTICODE SIGNATURE ---\n";
pub const MOCK_SIG_MAGIC_END: &[u8] = b"\n--- END CERCANO AUTHENTICODE SIGNATURE ---\n";

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("El sello de tiempo RFC 3161 es obligatorio para la firma Authenticode")]
    MissingTimestampUrl,

    #[error("Driver de firma no soportado: '{0}'. Drivers disponibles: 'mock', 'signtool', 'osslsigncode'")]
    UnsupportedDriver(String),

    #[error("El certificado de firma no fue especificado ni encontrado en ${ENV_CERT_PATH}")]
    MissingCertificate,

    #[error("El archivo de certificado de firma no existe: '{0}'")]
    CertificateNotFound(PathBuf),

    #[error("Herramienta de firma '{tool}' no encontrada en el PATH: {source}")]
    ToolNotFound {
        tool: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Fallo al ejecutar el comando de firma ({driver}, código: {exit_code:?}): {stderr}")]
    SignCommandFailed {
        driver: String,
        exit_code: Option<i32>,
        stderr: String,
    },

    #[error("Fallo en la verificación de firma Authenticode ({driver}, código: {exit_code:?}): {stderr}")]
    VerifyCommandFailed {
        driver: String,
        exit_code: Option<i32>,
        stderr: String,
    },

    #[error("Verificación de firma fallida: {0}")]
    VerificationFailed(String),

    #[error("Error de E/S en '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Error de serialización JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Drivers soportados para la firma de código Authenticode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningDriver {
    #[serde(rename = "signtool")]
    Signtool,
    #[serde(rename = "osslsigncode")]
    OsslSignCode,
    #[serde(rename = "mock")]
    Mock,
}

impl SigningDriver {
    pub fn as_str(&self) -> &'static str {
        match self {
            SigningDriver::Signtool => "signtool",
            SigningDriver::OsslSignCode => "osslsigncode",
            SigningDriver::Mock => "mock",
        }
    }
}

impl FromStr for SigningDriver {
    type Err = SigningError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().trim() {
            "signtool" => Ok(SigningDriver::Signtool),
            "osslsigncode" => Ok(SigningDriver::OsslSignCode),
            "mock" => Ok(SigningDriver::Mock),
            other => Err(SigningError::UnsupportedDriver(other.to_string())),
        }
    }
}

/// Trait abstracto para firmantes de código Authenticode enchufables.
pub trait CodeSigner: Debug + Send + Sync {
    /// Driver utilizado por este firmante.
    fn driver(&self) -> SigningDriver;

    /// URL del servidor de sellado de tiempo RFC 3161 configurado.
    fn timestamp_url(&self) -> &str;

    /// Aplica la firma Authenticode sobre el artefacto destino en disco.
    fn sign(&self, target_path: &Path) -> Result<(), SigningError>;

    /// Verifica que el artefacto destino contenga una firma Authenticode válida y no adulterada.
    fn verify(&self, target_path: &Path) -> Result<(), SigningError>;

    /// Ejecuta la firma seguida inmediatamente por la verificación obligatoria.
    fn sign_and_verify(&self, target_path: &Path) -> Result<(), SigningError> {
        self.sign(target_path)?;
        self.verify(target_path)?;
        Ok(())
    }
}

/// Estructura de carga útil almacenada en el bloque de firma de prueba Mock.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MockSignaturePayload {
    pub version: String,
    pub driver: String,
    pub original_sha256: String,
    pub content_length: usize,
    pub timestamp_url: String,
    pub timestamp_rfc3161: String,
    pub cert_subject: String,
}

/// Implementación determinista en memoria/archivo para pruebas en CI y desarrollo.
#[derive(Debug, Clone)]
pub struct MockSigner {
    pub timestamp_url: String,
    pub cert_name: String,
    pub fail_on_sign: bool,
    pub fail_on_verify: bool,
}

impl MockSigner {
    pub fn new(timestamp_url: String) -> Result<Self, SigningError> {
        if timestamp_url.trim().is_empty() {
            return Err(SigningError::MissingTimestampUrl);
        }
        let fail_sign = std::env::var("CERCANO_MOCK_SIGN_FAIL").is_ok();
        let fail_verify = std::env::var("CERCANO_MOCK_VERIFY_FAIL").is_ok();
        Ok(Self {
            timestamp_url,
            cert_name: "CN=Cercano Test Code Signing, O=Cercano Contributors, C=ES".to_string(),
            fail_on_sign: fail_sign,
            fail_on_verify: fail_verify,
        })
    }

    pub fn new_with_flags(
        timestamp_url: String,
        cert_name: Option<String>,
        fail_on_sign: bool,
        fail_on_verify: bool,
    ) -> Result<Self, SigningError> {
        if timestamp_url.trim().is_empty() {
            return Err(SigningError::MissingTimestampUrl);
        }
        Ok(Self {
            timestamp_url,
            cert_name: cert_name.unwrap_or_else(|| {
                "CN=Cercano Test Code Signing, O=Cercano Contributors, C=ES".to_string()
            }),
            fail_on_sign,
            fail_on_verify,
        })
    }
}

fn compute_sha256_internal(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

impl CodeSigner for MockSigner {
    fn driver(&self) -> SigningDriver {
        SigningDriver::Mock
    }

    fn timestamp_url(&self) -> &str {
        &self.timestamp_url
    }

    fn sign(&self, target_path: &Path) -> Result<(), SigningError> {
        if self.fail_on_sign || std::env::var("CERCANO_MOCK_SIGN_FAIL").is_ok() {
            return Err(SigningError::SignCommandFailed {
                driver: "mock".to_string(),
                exit_code: Some(1),
                stderr:
                    "Fallo simulado en la firma de código (MockSigner / CERCANO_MOCK_SIGN_FAIL)"
                        .to_string(),
            });
        }

        let content = fs::read(target_path).map_err(|source| SigningError::Io {
            path: target_path.to_path_buf(),
            source,
        })?;

        // Validar que no contenga ya un bloque de firma
        if find_subsequence(&content, MOCK_SIG_MAGIC_START).is_some() {
            return Err(SigningError::VerificationFailed(
                "El archivo ya contiene un bloque de firma Authenticode".to_string(),
            ));
        }

        let original_sha256 = compute_sha256_internal(&content);
        let payload = MockSignaturePayload {
            version: "1.0.0".to_string(),
            driver: "mock".to_string(),
            original_sha256,
            content_length: content.len(),
            timestamp_url: self.timestamp_url.clone(),
            timestamp_rfc3161: chrono::Utc::now().to_rfc3339(),
            cert_subject: self.cert_name.clone(),
        };

        let payload_json = serde_json::to_string_pretty(&payload)?;

        let mut signed_data = Vec::with_capacity(
            content.len()
                + MOCK_SIG_MAGIC_START.len()
                + payload_json.len()
                + MOCK_SIG_MAGIC_END.len(),
        );
        signed_data.extend_from_slice(&content);
        signed_data.extend_from_slice(MOCK_SIG_MAGIC_START);
        signed_data.extend_from_slice(payload_json.as_bytes());
        signed_data.extend_from_slice(MOCK_SIG_MAGIC_END);

        fs::write(target_path, &signed_data).map_err(|source| SigningError::Io {
            path: target_path.to_path_buf(),
            source,
        })?;

        Ok(())
    }

    fn verify(&self, target_path: &Path) -> Result<(), SigningError> {
        if self.fail_on_verify || std::env::var("CERCANO_MOCK_VERIFY_FAIL").is_ok() {
            return Err(SigningError::VerifyCommandFailed {
                driver: "mock".to_string(),
                exit_code: Some(1),
                stderr: "Fallo simulado en la verificación de código (MockSigner / CERCANO_MOCK_VERIFY_FAIL)"
                    .to_string(),
            });
        }

        let bytes = fs::read(target_path).map_err(|source| SigningError::Io {
            path: target_path.to_path_buf(),
            source,
        })?;

        let start_pos = find_subsequence(&bytes, MOCK_SIG_MAGIC_START).ok_or_else(|| {
            SigningError::VerificationFailed(
                "No se encontró encabezado de firma Authenticode en el archivo".to_string(),
            )
        })?;

        let after_start = start_pos + MOCK_SIG_MAGIC_START.len();
        let end_rel_pos =
            find_subsequence(&bytes[after_start..], MOCK_SIG_MAGIC_END).ok_or_else(|| {
                SigningError::VerificationFailed(
                    "No se encontró delimitador de cierre de firma Authenticode".to_string(),
                )
            })?;

        let end_pos = after_start + end_rel_pos;
        let expected_end = end_pos + MOCK_SIG_MAGIC_END.len();

        // Validar que no existan bytes adulterados agregados al final tras el bloque de firma
        if expected_end != bytes.len() {
            return Err(SigningError::VerificationFailed(
                "El archivo tiene datos no autorizados añadidos con posterioridad a la firma Authenticode"
                    .to_string(),
            ));
        }

        let original_content = &bytes[..start_pos];
        let payload_slice = &bytes[after_start..end_pos];

        let payload: MockSignaturePayload = serde_json::from_slice(payload_slice).map_err(|e| {
            SigningError::VerificationFailed(format!("Carga útil de firma corrupta: {}", e))
        })?;

        // 1. Validar presencia de sello de tiempo RFC 3161
        if payload.timestamp_url.trim().is_empty() {
            return Err(SigningError::VerificationFailed(
                "El bloque de firma no incluye un sello de tiempo RFC 3161 válido".to_string(),
            ));
        }

        // 2. Validar tamaño del contenido original
        if payload.content_length != original_content.len() {
            return Err(SigningError::VerificationFailed(format!(
                "La longitud del contenido original ({}) no coincide con la firma ({})",
                original_content.len(),
                payload.content_length
            )));
        }

        // 3. Validar integridad de hash SHA-256 (alteración de 1 byte produce fallo de verificación)
        let actual_sha256 = compute_sha256_internal(original_content);
        if actual_sha256 != payload.original_sha256 {
            return Err(SigningError::VerificationFailed(format!(
                "Firma adulterada o contenido modificado: hash esperado {} != hash actual {}",
                payload.original_sha256, actual_sha256
            )));
        }

        Ok(())
    }
}

/// Implementación para osslsigncode (multiplataforma / Linux / CI).
#[derive(Debug, Clone)]
pub struct OsslSignCodeSigner {
    pub timestamp_url: String,
    pub cert_path: PathBuf,
    pub cert_pass: Option<String>,
}

impl OsslSignCodeSigner {
    pub fn new(
        timestamp_url: String,
        cert_path: PathBuf,
        cert_pass: Option<String>,
    ) -> Result<Self, SigningError> {
        if timestamp_url.trim().is_empty() {
            return Err(SigningError::MissingTimestampUrl);
        }
        if !cert_path.is_file() {
            return Err(SigningError::CertificateNotFound(cert_path));
        }
        Ok(Self {
            timestamp_url,
            cert_path,
            cert_pass,
        })
    }
}

impl CodeSigner for OsslSignCodeSigner {
    fn driver(&self) -> SigningDriver {
        SigningDriver::OsslSignCode
    }

    fn timestamp_url(&self) -> &str {
        &self.timestamp_url
    }

    fn sign(&self, target_path: &Path) -> Result<(), SigningError> {
        let temp_signed = target_path.with_extension("signed.tmp");

        let mut cmd = Command::new("osslsigncode");
        cmd.arg("sign")
            .arg("-h")
            .arg("sha256")
            .arg("-ts")
            .arg(&self.timestamp_url)
            .arg("-pkcs12")
            .arg(&self.cert_path);

        if let Some(ref pass) = self.cert_pass {
            cmd.arg("-pass").arg(pass);
        }

        cmd.arg("-in")
            .arg(target_path)
            .arg("-out")
            .arg(&temp_signed);

        let output = cmd.output().map_err(|e| SigningError::ToolNotFound {
            tool: "osslsigncode".to_string(),
            source: e,
        })?;

        if !output.status.success() {
            let stderr_raw = String::from_utf8_lossy(&output.stderr).to_string();
            let stderr_clean = sanitize_secret(&stderr_raw, self.cert_pass.as_deref());
            let _ = fs::remove_file(&temp_signed);
            return Err(SigningError::SignCommandFailed {
                driver: "osslsigncode".to_string(),
                exit_code: output.status.code(),
                stderr: stderr_clean,
            });
        }

        // Reemplazar archivo original con el archivo firmado de forma atómica
        fs::rename(&temp_signed, target_path).map_err(|source| SigningError::Io {
            path: target_path.to_path_buf(),
            source,
        })?;

        Ok(())
    }

    fn verify(&self, target_path: &Path) -> Result<(), SigningError> {
        let mut cmd = Command::new("osslsigncode");
        cmd.arg("verify").arg("-in").arg(target_path);

        let output = cmd.output().map_err(|e| SigningError::ToolNotFound {
            tool: "osslsigncode".to_string(),
            source: e,
        })?;

        if !output.status.success() {
            let stderr_raw = String::from_utf8_lossy(&output.stderr).to_string();
            let stderr_clean = sanitize_secret(&stderr_raw, self.cert_pass.as_deref());
            return Err(SigningError::VerifyCommandFailed {
                driver: "osslsigncode".to_string(),
                exit_code: output.status.code(),
                stderr: stderr_clean,
            });
        }

        Ok(())
    }
}

/// Implementación para Microsoft signtool.exe en entornos Windows.
#[derive(Debug, Clone)]
pub struct SigntoolSigner {
    pub timestamp_url: String,
    pub cert_path: PathBuf,
    pub cert_pass: Option<String>,
}

impl SigntoolSigner {
    pub fn new(
        timestamp_url: String,
        cert_path: PathBuf,
        cert_pass: Option<String>,
    ) -> Result<Self, SigningError> {
        if timestamp_url.trim().is_empty() {
            return Err(SigningError::MissingTimestampUrl);
        }
        if !cert_path.is_file() {
            return Err(SigningError::CertificateNotFound(cert_path));
        }
        Ok(Self {
            timestamp_url,
            cert_path,
            cert_pass,
        })
    }
}

impl CodeSigner for SigntoolSigner {
    fn driver(&self) -> SigningDriver {
        SigningDriver::Signtool
    }

    fn timestamp_url(&self) -> &str {
        &self.timestamp_url
    }

    fn sign(&self, target_path: &Path) -> Result<(), SigningError> {
        let mut cmd = Command::new("signtool");
        cmd.arg("sign")
            .arg("/fd")
            .arg("sha256")
            .arg("/tr")
            .arg(&self.timestamp_url)
            .arg("/td")
            .arg("sha256")
            .arg("/f")
            .arg(&self.cert_path);

        if let Some(ref pass) = self.cert_pass {
            cmd.arg("/p").arg(pass);
        }

        cmd.arg(target_path);

        let output = cmd.output().map_err(|e| SigningError::ToolNotFound {
            tool: "signtool".to_string(),
            source: e,
        })?;

        if !output.status.success() {
            let stderr_raw = String::from_utf8_lossy(&output.stderr).to_string();
            let stderr_clean = sanitize_secret(&stderr_raw, self.cert_pass.as_deref());
            return Err(SigningError::SignCommandFailed {
                driver: "signtool".to_string(),
                exit_code: output.status.code(),
                stderr: stderr_clean,
            });
        }

        Ok(())
    }

    fn verify(&self, target_path: &Path) -> Result<(), SigningError> {
        // Intento 1: signtool verify /pa /v
        let mut cmd = Command::new("signtool");
        cmd.arg("verify").arg("/pa").arg("/v").arg(target_path);

        if let Ok(output) = cmd.output() {
            if output.status.success() {
                return Ok(());
            }
        }

        // Intento 2: Fallback con PowerShell Get-AuthenticodeSignature (en Windows)
        if cfg!(windows) {
            let ps_script = format!(
                "$sig = Get-AuthenticodeSignature -LiteralPath '{}'; if ($sig.Status -ne 'Valid') {{ Write-Error ($sig.StatusMessage); exit 1 }}",
                target_path.display()
            );
            let ps_output = Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
                .output();

            if let Ok(output) = ps_output {
                if output.status.success() {
                    return Ok(());
                } else {
                    let err = String::from_utf8_lossy(&output.stderr).to_string();
                    return Err(SigningError::VerifyCommandFailed {
                        driver: "signtool/powershell".to_string(),
                        exit_code: output.status.code(),
                        stderr: err,
                    });
                }
            }
        }

        Err(SigningError::VerifyCommandFailed {
            driver: "signtool".to_string(),
            exit_code: Some(1),
            stderr: "Verificación Authenticode fallida con signtool".to_string(),
        })
    }
}

/// Resuelve y construye una instancia de `CodeSigner` a partir de las opciones dadas y el entorno.
pub fn resolve_signer_from_options(
    driver_opt: Option<&str>,
    timestamp_url_opt: Option<&str>,
    cert_path_opt: Option<&Path>,
    cert_pass_opt: Option<&str>,
) -> Result<Arc<dyn CodeSigner>, SigningError> {
    // 1. Sello de tiempo RFC 3161 obligatorio
    let timestamp_url = match timestamp_url_opt {
        Some(url) if !url.trim().is_empty() => url.trim().to_string(),
        _ => return Err(SigningError::MissingTimestampUrl),
    };

    // 2. Determinar driver
    let driver = match driver_opt {
        Some(d) => SigningDriver::from_str(d)?,
        None => {
            if cfg!(windows) {
                SigningDriver::Signtool
            } else {
                SigningDriver::OsslSignCode
            }
        }
    };

    // 3. Aislamiento de secretos: cert_path y cert_pass provienen de opciones o variables seguras del entorno
    let cert_path = cert_path_opt.map(|p| p.to_path_buf()).or_else(|| {
        std::env::var(ENV_CERT_PATH)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(PathBuf::from)
    });

    let cert_pass = cert_pass_opt.map(|s| s.to_string()).or_else(|| {
        std::env::var(ENV_CERT_PASS)
            .ok()
            .filter(|v| !v.trim().is_empty())
    });

    match driver {
        SigningDriver::Mock => {
            let cert_name = cert_path
                .as_ref()
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                .map(|name| format!("CN={}, O=Cercano Contributors", name));
            let signer = MockSigner::new_with_flags(
                timestamp_url,
                cert_name,
                std::env::var("CERCANO_MOCK_SIGN_FAIL").is_ok(),
                std::env::var("CERCANO_MOCK_VERIFY_FAIL").is_ok(),
            )?;
            Ok(Arc::new(signer))
        }
        SigningDriver::OsslSignCode => {
            let path = cert_path.ok_or(SigningError::MissingCertificate)?;
            let signer = OsslSignCodeSigner::new(timestamp_url, path, cert_pass)?;
            Ok(Arc::new(signer))
        }
        SigningDriver::Signtool => {
            let path = cert_path.ok_or(SigningError::MissingCertificate)?;
            let signer = SigntoolSigner::new(timestamp_url, path, cert_pass)?;
            Ok(Arc::new(signer))
        }
    }
}

/// Busca la primera ocurrencia de una subsecuencia de bytes dentro de un búfer.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Sanitiza cadenas de salida eliminando contraseñas o secretos en texto plano.
fn sanitize_secret(text: &str, secret: Option<&str>) -> String {
    match secret {
        Some(s) if !s.is_empty() => text.replace(s, "[REDACTED]"),
        _ => text.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_mock_signer_success() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test_app.exe");
        fs::write(&file_path, b"MZ_FAKE_PE_HEADER_CONTENT_FOR_TESTING").unwrap();

        let signer = MockSigner::new(DEFAULT_TIMESTAMP_URL.to_string()).unwrap();
        assert_eq!(signer.driver(), SigningDriver::Mock);
        assert_eq!(signer.timestamp_url(), DEFAULT_TIMESTAMP_URL);

        // Firmar
        signer.sign(&file_path).expect("sign should succeed");

        // El contenido del archivo debe contener el bloque de firma
        let signed_bytes = fs::read(&file_path).unwrap();
        assert!(find_subsequence(&signed_bytes, MOCK_SIG_MAGIC_START).is_some());
        assert!(find_subsequence(&signed_bytes, MOCK_SIG_MAGIC_END).is_some());

        // Verificar inmediatamente
        signer.verify(&file_path).expect("verify should succeed");
    }

    #[test]
    fn test_mock_signer_requires_timestamp() {
        let res_empty = MockSigner::new("   ".to_string());
        assert!(matches!(res_empty, Err(SigningError::MissingTimestampUrl)));

        let res_none = resolve_signer_from_options(Some("mock"), None, None, None);
        assert!(matches!(res_none, Err(SigningError::MissingTimestampUrl)));

        let res_empty_str = resolve_signer_from_options(Some("mock"), Some(""), None, None);
        assert!(matches!(
            res_empty_str,
            Err(SigningError::MissingTimestampUrl)
        ));
    }

    #[test]
    fn test_mock_signer_tampered_content_fails_verification() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("tampered_app.exe");
        fs::write(&file_path, b"ORIGINAL_VALID_BINARY_PAYLOAD_123456789").unwrap();

        let signer = MockSigner::new(DEFAULT_TIMESTAMP_URL.to_string()).unwrap();
        signer.sign(&file_path).unwrap();

        // Alterar 1 solo byte del contenido original
        let mut signed_bytes = fs::read(&file_path).unwrap();
        signed_bytes[0] ^= 0xFF; // Flip bits del primer byte
        fs::write(&file_path, &signed_bytes).unwrap();

        // La verificación debe fallar obligatoriamente
        let verify_res = signer.verify(&file_path);
        assert!(verify_res.is_err());
        let err_msg = format!("{}", verify_res.unwrap_err());
        assert!(
            err_msg.contains("Firma adulterada") || err_msg.contains("modificado"),
            "Error inesperado: {}",
            err_msg
        );
    }

    #[test]
    fn test_mock_signer_appended_bytes_fails_verification() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("tampered_app.exe");
        fs::write(&file_path, b"ORIGINAL_VALID_BINARY_PAYLOAD").unwrap();

        let signer = MockSigner::new(DEFAULT_TIMESTAMP_URL.to_string()).unwrap();
        signer.sign(&file_path).unwrap();

        // Añadir 1 byte malicioso tras la firma
        let mut signed_bytes = fs::read(&file_path).unwrap();
        signed_bytes.push(0xAA);
        fs::write(&file_path, &signed_bytes).unwrap();

        let verify_res = signer.verify(&file_path);
        assert!(verify_res.is_err());
        let err_msg = format!("{}", verify_res.unwrap_err());
        assert!(
            err_msg.contains("datos no autorizados añadidos"),
            "Error inesperado: {}",
            err_msg
        );
    }

    #[test]
    fn test_mock_signer_simulated_failures() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("fail_test.exe");
        fs::write(&file_path, b"SAMPLE").unwrap();

        let fail_sign_signer = MockSigner::new_with_flags(
            DEFAULT_TIMESTAMP_URL.to_string(),
            None,
            true, // fail on sign
            false,
        )
        .unwrap();

        let sign_err = fail_sign_signer.sign(&file_path);
        assert!(matches!(
            sign_err,
            Err(SigningError::SignCommandFailed { .. })
        ));

        let fail_verify_signer = MockSigner::new_with_flags(
            DEFAULT_TIMESTAMP_URL.to_string(),
            None,
            false,
            true, // fail on verify
        )
        .unwrap();

        let ok_signer = MockSigner::new(DEFAULT_TIMESTAMP_URL.to_string()).unwrap();
        ok_signer.sign(&file_path).unwrap();

        let verify_err = fail_verify_signer.verify(&file_path);
        assert!(matches!(
            verify_err,
            Err(SigningError::VerifyCommandFailed { .. })
        ));
    }

    #[test]
    fn test_secret_isolation_env_vars() {
        let dir = tempdir().unwrap();
        let cert_file = dir.path().join("my-test-cert.pfx");
        fs::write(&cert_file, b"DUMMY_CERT_DATA").unwrap();

        // Configurar variables seguras de entorno
        std::env::set_var(ENV_CERT_PATH, cert_file.to_str().unwrap());
        std::env::set_var(ENV_CERT_PASS, "supersecretpassword123");

        let signer =
            resolve_signer_from_options(Some("mock"), Some(DEFAULT_TIMESTAMP_URL), None, None)
                .expect("should resolve mock signer");

        assert_eq!(signer.driver(), SigningDriver::Mock);

        // Limpiar entorno
        std::env::remove_var(ENV_CERT_PATH);
        std::env::remove_var(ENV_CERT_PASS);
    }

    #[test]
    fn test_driver_parsing() {
        assert_eq!(
            SigningDriver::from_str("mock").unwrap(),
            SigningDriver::Mock
        );
        assert_eq!(
            SigningDriver::from_str("signtool").unwrap(),
            SigningDriver::Signtool
        );
        assert_eq!(
            SigningDriver::from_str("osslsigncode").unwrap(),
            SigningDriver::OsslSignCode
        );
        assert!(SigningDriver::from_str("invalid_driver").is_err());
    }
}
