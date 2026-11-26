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
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use thiserror::Error;
use tokio::sync::{mpsc, Semaphore};
use tracing::{error, info};

use audit_core::{Actor, Category, EventInput, Outcome, Source, Subject};

use crate::config::Config;
use crate::profile::{sanitize_profile, CercanoProfile, ProfileRole, SignedCercanoProfile};

pub const DEFAULT_DEV_SIGNING_KEY_BYTES: [u8; 32] = [42u8; 32];
pub const DEFAULT_DEV_KEY_ID: &str = "cercano-dev-key";
pub const DEFAULT_SIGNED_PROFILE_NAME: &str = "cercano-profile.signed.json";
pub const DEFAULT_MANIFEST_NAME: &str = "build-manifest.json";
pub const DEFAULT_CHECKSUMS_NAME: &str = "SHA256SUMS";

#[derive(Debug, Error)]
pub enum BuildServiceError {
    #[error("Error de E/S en '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Error de serialización JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Error de validación de perfil: {0}")]
    ProfileValidation(#[from] crate::profile::ProfileValidationError),

    #[error("Error de verificación/firma de perfil: {0}")]
    ProfileVerification(#[from] crate::profile::ProfileVerificationError),

    #[error("Error en base de datos: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Error empaquetando archivo ZIP: {0}")]
    Zip(String),

    #[error("Formato inválido de clave de firma: {0}")]
    InvalidSigningKey(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildArtifactInfo {
    pub file_name: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildManifest {
    pub schema_version: String,
    pub build_id: String,
    pub profile_id: String,
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    pub version: String,
    pub strategy: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
    pub artifacts: Vec<BuildArtifactInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildJobRecord {
    pub id: String,
    pub user_id: String,
    pub role: String,
    pub profile_id: String,
    pub status: String,
    pub artifact_path: Option<String>,
    pub error_message: Option<String>,
    pub logs: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub expires_at: Option<String>,
}

pub struct BuildTask {
    pub job_id: String,
    pub trace_id: String,
    pub user_id: String,
    pub username: String,
    pub user_role: String,
    pub client_ip: Option<String>,
    pub profile: CercanoProfile,
    pub existing_signed: Option<SignedCercanoProfile>,
    pub base_binary_path: Option<PathBuf>,
}

pub struct BuildQueue {
    sender: mpsc::Sender<BuildTask>,
    concurrency_semaphore: Arc<Semaphore>,
    builds_dir: PathBuf,
    audit: Arc<audit_core::AuditStore>,
}

impl BuildQueue {
    pub fn new(config: &Config, db: SqlitePool, audit: Arc<audit_core::AuditStore>) -> Self {
        let concurrency = config.build_concurrency.max(1);
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let (sender, mut receiver) = mpsc::channel::<BuildTask>(100);

        let builds_dir = PathBuf::from(&config.builds_dir);
        let signing_key_path = config.build_signing_key_path.clone();
        if signing_key_path.is_none() && !dev_signing_key_allowed() {
            error!("CERCANO_BUILD_SIGNING_KEY_PATH no está configurado: los builds fallarán hasta configurarlo");
        }

        let sem_clone = semaphore.clone();
        let builds_dir_clone = builds_dir.clone();
        let audit_worker = audit.clone();

        tokio::spawn(async move {
            info!(
                concurrency = concurrency,
                dir = %builds_dir_clone.display(),
                "Iniciando servicio de compilación y empaquetado asíncrono"
            );

            while let Some(task) = receiver.recv().await {
                let sem_permit = match sem_clone.clone().acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => {
                        error!("Semáforo de concurrencia de build cerrado");
                        break;
                    }
                };

                let db = db.clone();
                let builds_dir = builds_dir_clone.clone();
                let signing_key_path = signing_key_path.clone();
                let audit_worker = audit_worker.clone();

                tokio::spawn(async move {
                    let _permit = sem_permit;
                    process_build_task(task, db, audit_worker, builds_dir, signing_key_path).await;
                });
            }
        });

        Self {
            sender,
            concurrency_semaphore: semaphore,
            builds_dir,
            audit,
        }
    }

    pub async fn enqueue(&self, task: BuildTask) -> Result<(), String> {
        self.sender
            .send(task)
            .await
            .map_err(|e| format!("Fallo al encolar trabajo de compilación: {}", e))
    }

    pub fn builds_dir(&self) -> &Path {
        &self.builds_dir
    }

    pub fn audit(&self) -> &Arc<audit_core::AuditStore> {
        &self.audit
    }

    pub fn available_permits(&self) -> usize {
        self.concurrency_semaphore.available_permits()
    }
}

pub fn compute_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in result {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// `CERCANO_ALLOW_DEV_SIGNING_KEY=1` permite firmar con la clave de desarrollo (solo pruebas).
pub fn dev_signing_key_allowed() -> bool {
    std::env::var("CERCANO_ALLOW_DEV_SIGNING_KEY").as_deref() == Ok("1")
}

pub fn load_signing_key(path: Option<&str>) -> Result<SigningKey, BuildServiceError> {
    load_signing_key_with(path, dev_signing_key_allowed())
}

fn load_signing_key_with(
    path: Option<&str>,
    allow_dev_key: bool,
) -> Result<SigningKey, BuildServiceError> {
    match path {
        Some(p) => {
            let data = fs::read(p).map_err(|source| BuildServiceError::Io {
                path: PathBuf::from(p),
                source,
            })?;
            if data.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&data);
                Ok(SigningKey::from_bytes(&arr))
            } else {
                Err(BuildServiceError::InvalidSigningKey(
                    "La clave de firma debe tener 32 bytes".to_string(),
                ))
            }
        }
        // La clave de desarrollo es pública: solo con opt-in explícito (pruebas).
        None if allow_dev_key => Ok(SigningKey::from_bytes(&DEFAULT_DEV_SIGNING_KEY_BYTES)),
        None => Err(BuildServiceError::InvalidSigningKey(
            "Falta CERCANO_BUILD_SIGNING_KEY_PATH: sin clave configurada no se firman perfiles"
                .to_string(),
        )),
    }
}

pub fn execute_build_bundle(
    job_id: &str,
    profile: &CercanoProfile,
    existing_signed: Option<SignedCercanoProfile>,
    base_binary_path: Option<&Path>,
    signing_key_path: Option<&str>,
    builds_dir: &Path,
) -> Result<(PathBuf, String), BuildServiceError> {
    let start_time = Instant::now();
    let mut logs = String::new();
    logs.push_str(&format!(
        "[{}] Iniciando compilación de instalador para job {}\n",
        Utc::now().to_rfc3339(),
        job_id
    ));

    // 1. Validar invariantes
    profile.validate()?;
    logs.push_str("Invariantes de perfil validados correctamente.\n");

    // 2. Firmar si es necesario
    let signed_profile = match (existing_signed, signing_key_path) {
        (Some(signed), None) => signed,
        _ => {
            let signing_key = load_signing_key(signing_key_path)?;
            let key_id = Some(DEFAULT_DEV_KEY_ID.to_string());
            profile.sign(&signing_key, key_id)?
        }
    };
    logs.push_str("Sobre de perfil firmado generado/verificado con Ed25519.\n");

    let role_str = match profile.role {
        ProfileRole::Soporte => "soporte",
        ProfileRole::Tecnico => "tecnico",
    };
    let version_str = &profile.schema_version;

    // 3. Crear directorio para el job
    let job_dir = builds_dir.join(job_id);
    let bundle_folder_name = format!("cercano-{}-{}", role_str, version_str);
    let target_dir = job_dir.join(&bundle_folder_name);
    fs::create_dir_all(&target_dir).map_err(|source| BuildServiceError::Io {
        path: target_dir.clone(),
        source,
    })?;

    let mut artifacts = Vec::new();

    // 4. Escribir perfil firmado
    let signed_profile_path = target_dir.join(DEFAULT_SIGNED_PROFILE_NAME);
    let signed_json = serde_json::to_string_pretty(&signed_profile)?;
    fs::write(&signed_profile_path, signed_json.as_bytes()).map_err(|source| {
        BuildServiceError::Io {
            path: signed_profile_path.clone(),
            source,
        }
    })?;

    let profile_hash = compute_sha256(signed_json.as_bytes());
    artifacts.push(BuildArtifactInfo {
        file_name: DEFAULT_SIGNED_PROFILE_NAME.to_string(),
        sha256: profile_hash,
        size_bytes: signed_json.len() as u64,
    });
    logs.push_str(&format!("Escrito {}\n", DEFAULT_SIGNED_PROFILE_NAME));

    // 5. Copiar binario base si existe
    if let Some(base_path) = base_binary_path {
        if base_path.is_file() {
            let file_name = base_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("cercano.exe");
            let dest_path = target_dir.join(file_name);
            fs::copy(base_path, &dest_path).map_err(|source| BuildServiceError::Io {
                path: dest_path.clone(),
                source,
            })?;
            let data = fs::read(&dest_path).map_err(|source| BuildServiceError::Io {
                path: dest_path.clone(),
                source,
            })?;
            artifacts.push(BuildArtifactInfo {
                file_name: file_name.to_string(),
                sha256: compute_sha256(&data),
                size_bytes: data.len() as u64,
            });
            logs.push_str(&format!("Empaquetado binario base {}\n", file_name));
        }
    }

    // 6. Generar build-manifest.json
    let manifest = BuildManifest {
        schema_version: "1.0.0".to_string(),
        build_id: job_id.to_string(),
        profile_id: profile.profile_id.clone(),
        role: role_str.to_string(),
        app_name: profile.identity.as_ref().and_then(|i| i.app_name.clone()),
        version: version_str.clone(),
        strategy: "A".to_string(),
        created_at: Utc::now().to_rfc3339(),
        signing_key_id: signed_profile.key_id.clone(),
        artifacts: artifacts.clone(),
    };
    let manifest_path = target_dir.join(DEFAULT_MANIFEST_NAME);
    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    fs::write(&manifest_path, manifest_json.as_bytes()).map_err(|source| {
        BuildServiceError::Io {
            path: manifest_path.clone(),
            source,
        }
    })?;
    logs.push_str(&format!("Escrito {}\n", DEFAULT_MANIFEST_NAME));

    // 7. Checksums SHA256SUMS
    let checksums_path = target_dir.join(DEFAULT_CHECKSUMS_NAME);
    let mut checksum_lines = Vec::new();
    for entry in fs::read_dir(&target_dir).map_err(|source| BuildServiceError::Io {
        path: target_dir.clone(),
        source,
    })? {
        let entry = entry.map_err(|source| BuildServiceError::Io {
            path: target_dir.clone(),
            source,
        })?;
        let p = entry.path();
        if p.is_file() {
            let fname = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if fname != DEFAULT_CHECKSUMS_NAME {
                let data = fs::read(&p).map_err(|source| BuildServiceError::Io {
                    path: p.clone(),
                    source,
                })?;
                checksum_lines.push((fname.to_string(), compute_sha256(&data)));
            }
        }
    }
    checksum_lines.sort_by(|a, b| a.0.cmp(&b.0));
    let mut checksums_content = String::new();
    for (name, hash) in checksum_lines {
        checksums_content.push_str(&format!("{}  {}\n", hash, name));
    }
    fs::write(&checksums_path, checksums_content.as_bytes()).map_err(|source| {
        BuildServiceError::Io {
            path: checksums_path.clone(),
            source,
        }
    })?;
    logs.push_str(&format!("Escrito {}\n", DEFAULT_CHECKSUMS_NAME));

    // 8. Empaquetar todo en ZIP para descarga directa
    let zip_filename = format!("cercano-{}-{}.zip", role_str, version_str);
    let zip_path = job_dir.join(&zip_filename);
    let zip_file = fs::File::create(&zip_path).map_err(|source| BuildServiceError::Io {
        path: zip_path.clone(),
        source,
    })?;

    let mut zip_writer = zip::ZipWriter::new(zip_file);
    let zip_options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    for entry in fs::read_dir(&target_dir).map_err(|source| BuildServiceError::Io {
        path: target_dir.clone(),
        source,
    })? {
        let entry = entry.map_err(|source| BuildServiceError::Io {
            path: target_dir.clone(),
            source,
        })?;
        let p = entry.path();
        if p.is_file() {
            let fname = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            let file_data = fs::read(&p).map_err(|source| BuildServiceError::Io {
                path: p.clone(),
                source,
            })?;
            zip_writer
                .start_file(fname, zip_options)
                .map_err(|e| BuildServiceError::Zip(e.to_string()))?;
            zip_writer
                .write_all(&file_data)
                .map_err(|source| BuildServiceError::Io {
                    path: zip_path.clone(),
                    source,
                })?;
        }
    }
    zip_writer
        .finish()
        .map_err(|e| BuildServiceError::Zip(e.to_string()))?;

    let elapsed = start_time.elapsed().as_millis();
    logs.push_str(&format!(
        "Generación exitosa completada en {} ms. Artefacto: {}\n",
        elapsed,
        zip_path.display()
    ));

    Ok((zip_path, logs))
}

async fn process_build_task(
    task: BuildTask,
    db: SqlitePool,
    audit: Arc<audit_core::AuditStore>,
    builds_dir: PathBuf,
    signing_key_path: Option<String>,
) {
    let start_instant = Instant::now();
    let now = Utc::now().to_rfc3339();

    let role_str = match task.profile.role {
        ProfileRole::Soporte => "soporte",
        ProfileRole::Tecnico => "tecnico",
    };

    let actor = Actor::with_details(
        &task.user_id,
        "user",
        Some(task.username.clone()),
        task.client_ip.clone(),
    );
    let subject = Subject::with_details(&task.job_id, "build_job", Some(role_str.to_string()));

    // Marcar job como running
    let _ = sqlx::query("UPDATE build_jobs SET status = 'running', started_at = ? WHERE id = ?")
        .bind(&now)
        .bind(&task.job_id)
        .execute(&db)
        .await;

    // Emitir build.started
    let started_input = EventInput::new(
        task.trace_id.clone(),
        Source::Builder,
        Category::Build,
        "build.started",
        actor.clone(),
        Outcome::Success,
        serde_json::json!({
            "job_id": task.job_id,
            "installer_id": task.job_id,
            "role": role_str,
            "profile_id": task.profile.profile_id,
            "sanitized_profile": sanitize_profile(&task.profile),
        }),
    )
    .with_subject(subject.clone());

    if let Err(e) = audit.append(started_input).await {
        error!(job_id = %task.job_id, error = ?e, "Error al registrar evento build.started en auditoría");
    }

    let res = execute_build_bundle(
        &task.job_id,
        &task.profile,
        task.existing_signed,
        task.base_binary_path.as_deref(),
        signing_key_path.as_deref(),
        &builds_dir,
    );

    let duration_ms = start_instant.elapsed().as_millis() as u64;
    let completed_at = Utc::now().to_rfc3339();

    match res {
        Ok((artifact_path, logs)) => {
            let path_str = artifact_path.to_string_lossy().to_string();
            let (sha256, size_bytes) = match fs::read(&artifact_path) {
                Ok(b) => (compute_sha256(&b), b.len() as u64),
                Err(_) => (String::new(), 0u64),
            };

            let _ = sqlx::query(
                r#"
                UPDATE build_jobs 
                SET status = 'completed', completed_at = ?, artifact_path = ?, logs = ?
                WHERE id = ?
                "#,
            )
            .bind(&completed_at)
            .bind(&path_str)
            .bind(&logs)
            .bind(&task.job_id)
            .execute(&db)
            .await;

            // Emitir build.completed
            let completed_input = EventInput::new(
                task.trace_id.clone(),
                Source::Builder,
                Category::Build,
                "build.completed",
                actor,
                Outcome::Success,
                serde_json::json!({
                    "job_id": task.job_id,
                    "installer_id": task.job_id,
                    "role": role_str,
                    "profile_id": task.profile.profile_id,
                    "sha256": sha256,
                    "size_bytes": size_bytes,
                    "duration_ms": duration_ms,
                    "sanitized_profile": sanitize_profile(&task.profile),
                    "artifact_path": path_str,
                }),
            )
            .with_subject(subject);

            if let Err(e) = audit.append(completed_input).await {
                error!(job_id = %task.job_id, error = ?e, "Error al registrar evento build.completed en auditoría");
            }

            info!(job_id = %task.job_id, "Trabajo de compilación completado con éxito");
        }
        Err(err) => {
            let err_msg = err.to_string();
            let _ = sqlx::query(
                r#"
                UPDATE build_jobs 
                SET status = 'failed', completed_at = ?, error_message = ?, logs = COALESCE(logs, '') || ?
                WHERE id = ?
                "#,
            )
            .bind(&completed_at)
            .bind(&err_msg)
            .bind(format!("\nERROR: {}", err_msg))
            .bind(&task.job_id)
            .execute(&db)
            .await;

            // Emitir build.failed
            let failed_input = EventInput::new(
                task.trace_id.clone(),
                Source::Builder,
                Category::Build,
                "build.failed",
                actor,
                Outcome::Failure,
                serde_json::json!({
                    "job_id": task.job_id,
                    "installer_id": task.job_id,
                    "role": role_str,
                    "profile_id": task.profile.profile_id,
                    "error": err_msg,
                    "duration_ms": duration_ms,
                    "sanitized_profile": sanitize_profile(&task.profile),
                }),
            )
            .with_subject(subject);

            if let Err(e) = audit.append(failed_input).await {
                error!(job_id = %task.job_id, error = ?e, "Error al registrar evento build.failed en auditoría");
            }

            error!(job_id = %task.job_id, error = %err_msg, "Trabajo de compilación falló");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_key_path_signing_fails_unless_dev_key_allowed() {
        assert!(matches!(
            load_signing_key_with(None, false),
            Err(BuildServiceError::InvalidSigningKey(_))
        ));
        assert!(load_signing_key_with(None, true).is_ok());
    }
}
