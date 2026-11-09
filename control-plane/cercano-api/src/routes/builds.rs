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
use std::path::PathBuf;

use audit_core::{Actor, Category, EventInput, Outcome, Source, Subject};
use axum::extract::{Path, Query, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::auth::{extract_client_ip, extract_trace_id, AuthenticatedUser};
use crate::builder::{BuildJobRecord, BuildTask};
use crate::profile::{sanitize_profile, CercanoProfile, ProfileRole, SignedCercanoProfile};
use crate::AppState;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum BuildPayloadInput {
    WrappedProfile { profile: CercanoProfile },
    WrappedSigned { profile: SignedCercanoProfile },
    DirectSigned(SignedCercanoProfile),
    DirectProfile(CercanoProfile),
}

impl BuildPayloadInput {
    pub fn extract(self) -> (CercanoProfile, Option<SignedCercanoProfile>) {
        match self {
            Self::WrappedProfile { profile } => (profile, None),
            Self::WrappedSigned { profile } => (profile.profile.clone(), Some(profile)),
            Self::DirectSigned(signed) => (signed.profile.clone(), Some(signed)),
            Self::DirectProfile(profile) => (profile, None),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnqueueBuildResponse {
    pub id: String,
    pub user_id: String,
    pub role: String,
    pub profile_id: String,
    pub status: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ListBuildsQuery {
    pub role: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub async fn check_build_create_permission(
    pool: &SqlitePool,
    user: &AuthenticatedUser,
    role: ProfileRole,
) -> Result<bool, sqlx::Error> {
    if user.role == "admin" {
        return Ok(true);
    }

    match role {
        ProfileRole::Tecnico => {
            // Solo administrador o permiso explícito builder:create:tecnico
            let row = sqlx::query(
                "SELECT 1 FROM user_permissions WHERE user_id = ? AND permission = 'builder:create:tecnico'",
            )
            .bind(&user.id)
            .fetch_optional(pool)
            .await?;
            Ok(row.is_some())
        }
        ProfileRole::Soporte => {
            // Rol soporte o permiso builder:create:soporte o builder:create:tecnico
            if user.role == "soporte" {
                return Ok(true);
            }
            let row = sqlx::query(
                "SELECT 1 FROM user_permissions WHERE user_id = ? AND permission IN ('builder:create:soporte', 'builder:create:tecnico')",
            )
            .bind(&user.id)
            .fetch_optional(pool)
            .await?;
            Ok(row.is_some())
        }
    }
}

pub async fn check_build_download_permission(
    pool: &SqlitePool,
    user: &AuthenticatedUser,
    job_user_id: &str,
) -> Result<bool, sqlx::Error> {
    if user.role == "admin" || user.id == job_user_id {
        return Ok(true);
    }

    let row = sqlx::query(
        "SELECT 1 FROM user_permissions WHERE user_id = ? AND permission = 'builder:download'",
    )
    .bind(&user.id)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

/// Encola un nuevo trabajo de generación con un payload de perfil (`profile`).
/// Valida esquema y roles. Retorna HTTP 202 Accepted con `id` de job.
pub async fn enqueue_build_handler(
    headers: HeaderMap,
    user: AuthenticatedUser,
    State(state): State<AppState>,
    Json(payload): Json<BuildPayloadInput>,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    let (profile, existing_signed) = payload.extract();

    // 1. Validar perfil y esquema
    if let Err(val_err) = profile.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "validation_error",
                "message": format!("Error de validación del perfil: {}", val_err)
            })),
        )
            .into_response();
    }

    // 2. Control de acceso RBAC
    let has_perm = match check_build_create_permission(&state.db, &user, profile.role).await {
        Ok(allowed) => allowed,
        Err(e) => {
            tracing::error!("Error consultando permisos de build: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "internal_error",
                    "message": "Error al verificar permisos"
                })),
            )
                .into_response();
        }
    };

    let role_str = match profile.role {
        ProfileRole::Soporte => "soporte",
        ProfileRole::Tecnico => "tecnico",
    };

    if !has_perm {
        // Registrar rechazo en auditoría
        let actor = Actor::with_details(
            &user.id,
            "user",
            Some(user.username.clone()),
            Some(client_ip),
        );
        let subject = Subject::with_details(
            format!("build:{}", role_str),
            "build_job",
            Some(role_str.to_string()),
        );

        let denied_input = EventInput::new(
            trace_id,
            Source::Api,
            Category::Auth,
            "auth.denied",
            actor,
            Outcome::Denied,
            json!({
                "error": "forbidden",
                "requested_role": role_str,
                "profile_id": profile.profile_id,
                "required_permission": if profile.role == ProfileRole::Tecnico {
                    "builder:create:tecnico"
                } else {
                    "builder:create:soporte"
                },
                "message": format!(
                    "Usuario '{}' (rol '{}') intentó solicitar build '{}' sin privilegios requeridos",
                    user.username, user.role, role_str
                )
            }),
        )
        .with_subject(subject);

        let _ = state.audit.append(denied_input).await;

        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "forbidden",
                "message": format!(
                    "Acceso denegado: se requieren permisos administrativos o rol técnico para solicitar instaladores '{}'",
                    role_str
                )
            })),
        )
            .into_response();
    }

    // 3. Crear registro del job
    let job_id = Uuid::now_v7().to_string();
    let created_at = Utc::now();
    let retention_secs = state.config.build_retention_secs as i64;
    let expires_at = created_at + chrono::Duration::seconds(retention_secs);

    let created_at_str = created_at.to_rfc3339();
    let expires_at_str = expires_at.to_rfc3339();

    let insert_res = sqlx::query(
        r#"
        INSERT INTO build_jobs (id, user_id, role, profile_id, status, created_at, expires_at)
        VALUES (?, ?, ?, ?, 'queued', ?, ?)
        "#,
    )
    .bind(&job_id)
    .bind(&user.id)
    .bind(role_str)
    .bind(&profile.profile_id)
    .bind(&created_at_str)
    .bind(&expires_at_str)
    .execute(&state.db)
    .await;

    if let Err(e) = insert_res {
        tracing::error!("Error insertando build job: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "database_error",
                "message": "Fallo al registrar trabajo de build"
            })),
        )
            .into_response();
    }

    // 4. Emitir evento auditado build.requested
    let actor = Actor::with_details(
        &user.id,
        "user",
        Some(user.username.clone()),
        Some(client_ip.clone()),
    );
    let subject = Subject::with_details(&job_id, "build_job", Some(role_str.to_string()));

    let req_input = EventInput::new(
        trace_id.clone(),
        Source::Api,
        Category::Build,
        "build.requested",
        actor,
        Outcome::Success,
        json!({
            "job_id": job_id,
            "installer_id": job_id,
            "role": role_str,
            "profile_id": profile.profile_id,
            "sanitized_profile": sanitize_profile(&profile),
        }),
    )
    .with_subject(subject);

    if let Err(e) = state.audit.append(req_input).await {
        tracing::error!("Error emitiendo evento build.requested: {:?}", e);
    }

    // 5. Encolar tarea asíncrona
    let task = BuildTask {
        job_id: job_id.clone(),
        trace_id,
        user_id: user.id.clone(),
        username: user.username.clone(),
        user_role: user.role.clone(),
        client_ip: Some(client_ip),
        profile: profile.clone(),
        existing_signed,
        base_binary_path: None,
    };

    if let Err(e) = state.build_queue.enqueue(task).await {
        tracing::error!("Error encolando tarea de build: {:?}", e);
        let _ =
            sqlx::query("UPDATE build_jobs SET status = 'failed', error_message = ? WHERE id = ?")
                .bind(&e)
                .bind(&job_id)
                .execute(&state.db)
                .await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "queue_error",
                "message": format!("Fallo al despachar trabajo a la cola: {}", e)
            })),
        )
            .into_response();
    }

    (
        StatusCode::ACCEPTED,
        Json(EnqueueBuildResponse {
            id: job_id,
            user_id: user.id,
            role: role_str.to_string(),
            profile_id: profile.profile_id,
            status: "queued".to_string(),
            created_at: created_at_str,
            expires_at: Some(expires_at_str),
        }),
    )
        .into_response()
}

/// Lista los trabajos de compilación/empaquetado recientes del usuario o sistema.
pub async fn list_builds_handler(
    user: AuthenticatedUser,
    State(state): State<AppState>,
    Query(query): Query<ListBuildsQuery>,
) -> Response {
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0).max(0);

    let is_admin = user.role == "admin";

    let mut sql = String::from(
        r#"
        SELECT id, user_id, role, profile_id, status, artifact_path, error_message, logs,
               created_at, started_at, completed_at, expires_at
        FROM build_jobs
        WHERE 1=1
        "#,
    );

    if !is_admin {
        sql.push_str(" AND user_id = ?");
    }

    if query.role.is_some() {
        sql.push_str(" AND role = ?");
    }

    if query.status.is_some() {
        sql.push_str(" AND status = ?");
    }

    sql.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

    let mut q = sqlx::query(&sql);

    if !is_admin {
        q = q.bind(&user.id);
    }
    if let Some(ref role) = query.role {
        q = q.bind(role);
    }
    if let Some(ref status) = query.status {
        q = q.bind(status);
    }
    q = q.bind(limit).bind(offset);

    let rows = match q.fetch_all(&state.db).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Error listando build jobs: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "database_error",
                    "message": "Fallo al consultar trabajos de build"
                })),
            )
                .into_response();
        }
    };

    let jobs: Vec<BuildJobRecord> = rows
        .into_iter()
        .map(|r| BuildJobRecord {
            id: r.get("id"),
            user_id: r.get("user_id"),
            role: r.get("role"),
            profile_id: r.get("profile_id"),
            status: r.get("status"),
            artifact_path: r.get("artifact_path"),
            error_message: r.get("error_message"),
            logs: r.get("logs"),
            created_at: r.get("created_at"),
            started_at: r.get("started_at"),
            completed_at: r.get("completed_at"),
            expires_at: r.get("expires_at"),
        })
        .collect();

    (StatusCode::OK, Json(jobs)).into_response()
}

/// Consulta el estado detallado del job (`queued`, `running`, `completed`, `failed`), timestamps, logs y metadatos.
pub async fn get_build_handler(
    user: AuthenticatedUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    let row = sqlx::query(
        r#"
        SELECT id, user_id, role, profile_id, status, artifact_path, error_message, logs,
               created_at, started_at, completed_at, expires_at
        FROM build_jobs
        WHERE id = ?
        "#,
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await;

    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "not_found",
                    "message": format!("Trabajo de build '{}' no encontrado", id)
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Error consultando build job {}: {:?}", id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "database_error",
                    "message": "Error consultando base de datos"
                })),
            )
                .into_response();
        }
    };

    let job = BuildJobRecord {
        id: row.get("id"),
        user_id: row.get("user_id"),
        role: row.get("role"),
        profile_id: row.get("profile_id"),
        status: row.get("status"),
        artifact_path: row.get("artifact_path"),
        error_message: row.get("error_message"),
        logs: row.get("logs"),
        created_at: row.get("created_at"),
        started_at: row.get("started_at"),
        completed_at: row.get("completed_at"),
        expires_at: row.get("expires_at"),
    };

    // Control de acceso: solo admin o creador del trabajo
    if user.role != "admin" && user.id != job.user_id {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "forbidden",
                "message": "No tiene permisos para consultar este trabajo de compilación"
            })),
        )
            .into_response();
    }

    (StatusCode::OK, Json(job)).into_response()
}

/// Descarga segura del paquete generado con control de caducidad y cabeceras adecuadas.
pub async fn download_build_handler(
    headers: HeaderMap,
    user: AuthenticatedUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    let row = sqlx::query(
        r#"
        SELECT id, user_id, role, profile_id, status, artifact_path, expires_at
        FROM build_jobs
        WHERE id = ?
        "#,
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await;

    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "not_found",
                    "message": format!("Trabajo de build '{}' no encontrado", id)
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Error consultando build job {} para descarga: {:?}", id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "database_error",
                    "message": "Error consultando base de datos"
                })),
            )
                .into_response();
        }
    };

    let job_user_id: String = row.get("user_id");
    let role: String = row.get("role");
    let profile_id: String = row.get("profile_id");
    let status: String = row.get("status");
    let artifact_path: Option<String> = row.get("artifact_path");
    let expires_at_str: Option<String> = row.get("expires_at");

    // 1. Control de acceso
    match check_build_download_permission(&state.db, &user, &job_user_id).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "forbidden",
                    "message": "No tiene permisos para descargar este artefacto"
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Error comprobando permisos de descarga: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "internal_error",
                    "message": "Error al verificar permisos"
                })),
            )
                .into_response();
        }
    }

    // 2. Comprobar estado
    if status == "revoked" {
        return (
            StatusCode::GONE,
            Json(json!({
                "error": "artifact_revoked",
                "message": "El instalador ha sido revocado y no puede ser descargado"
            })),
        )
            .into_response();
    }

    if status != "completed" {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "job_not_completed",
                "message": format!("El trabajo de compilación se encuentra en estado '{}', aún no completado", status)
            })),
        )
            .into_response();
    }

    // 3. Comprobar caducidad
    if let Some(ref exp_str) = expires_at_str {
        if let Ok(exp_dt) = DateTime::parse_from_rfc3339(exp_str) {
            if exp_dt.with_timezone(&Utc) < Utc::now() {
                return (
                    StatusCode::GONE,
                    Json(json!({
                        "error": "artifact_expired",
                        "message": format!("El artefacto generado caducó en {}", exp_str)
                    })),
                )
                    .into_response();
            }
        }
    }

    // 4. Comprobar archivo en disco
    let path = match artifact_path {
        Some(p) => PathBuf::from(p),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "artifact_missing",
                    "message": "Ruta de artefacto no configurada"
                })),
            )
                .into_response();
        }
    };

    if !path.is_file() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "file_not_found",
                "message": "El archivo de artefacto no fue encontrado en el almacenamiento"
            })),
        )
            .into_response();
    }

    let file_bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(
                "Error leyendo archivo de artefacto {}: {:?}",
                path.display(),
                e
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "io_error",
                    "message": "Error leyendo archivo de artefacto"
                })),
            )
                .into_response();
        }
    };

    let filename = path
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("cercano-{}-{}.zip", role, profile_id));

    let sha256 = crate::builder::compute_sha256(&file_bytes);
    let size_bytes = file_bytes.len() as u64;

    // 5. Emitir evento build.downloaded
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);
    let actor = Actor::with_details(
        &user.id,
        "user",
        Some(user.username.clone()),
        Some(client_ip),
    );
    let subject = Subject::with_details(&id, "build_job", Some(role.clone()));

    let download_input = EventInput::new(
        trace_id,
        Source::Api,
        Category::Build,
        "build.downloaded",
        actor,
        Outcome::Success,
        json!({
            "job_id": id,
            "installer_id": id,
            "role": role,
            "profile_id": profile_id,
            "sha256": sha256,
            "size_bytes": size_bytes,
            "file_name": filename,
        }),
    )
    .with_subject(subject);

    if let Err(e) = state.audit.append(download_input).await {
        tracing::error!("Error emitiendo evento build.downloaded: {:?}", e);
    }

    let mut response_headers = HeaderMap::new();
    response_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/zip"));
    response_headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store, must-revalidate"),
    );
    response_headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );

    let disposition = format!("attachment; filename=\"{}\"", filename);
    if let Ok(val) = HeaderValue::from_str(&disposition) {
        response_headers.insert(CONTENT_DISPOSITION, val);
    }

    response_headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&file_bytes.len().to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );

    (StatusCode::OK, response_headers, file_bytes).into_response()
}

#[derive(Debug, Deserialize, Default)]
pub struct RevokeBuildPayload {
    pub reason: Option<String>,
}

/// Revoca un trabajo o artefacto de compilación e instalador.
/// Actualiza el estado a 'revoked' y emite el evento auditado `build.revoked`.
pub async fn revoke_build_handler(
    headers: HeaderMap,
    user: AuthenticatedUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let row = sqlx::query(
        r#"
        SELECT id, user_id, role, profile_id, status
        FROM build_jobs
        WHERE id = ?
        "#,
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await;

    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "not_found",
                    "message": format!("Trabajo de build '{}' no encontrado", id)
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(
                "Error consultando build job {} para revocación: {:?}",
                id,
                e
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "database_error",
                    "message": "Error consultando base de datos"
                })),
            )
                .into_response();
        }
    };

    let job_user_id: String = row.get("user_id");
    let role: String = row.get("role");
    let profile_id: String = row.get("profile_id");
    let status: String = row.get("status");

    // 1. Control de acceso: admin, creador o permiso builder:revoke
    let is_owner = user.id == job_user_id;
    let is_admin = user.role == "admin";
    let has_revoke_perm = if !is_owner && !is_admin {
        let perm_row = sqlx::query(
            "SELECT 1 FROM user_permissions WHERE user_id = ? AND permission = 'builder:revoke'",
        )
        .bind(&user.id)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);
        perm_row.is_some()
    } else {
        true
    };

    if !has_revoke_perm {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "forbidden",
                "message": "No tiene permisos para revocar este instalador"
            })),
        )
            .into_response();
    }

    // 2. Si ya está revocado
    if status == "revoked" {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "already_revoked",
                "message": "El instalador ya se encuentra revocado"
            })),
        )
            .into_response();
    }

    let payload: Option<RevokeBuildPayload> = if !body.is_empty() {
        serde_json::from_slice(&body).ok()
    } else {
        None
    };

    let reason_str = payload
        .and_then(|p| p.reason)
        .unwrap_or_else(|| "Instalador revocado por el usuario".to_string());

    let revoked_at = Utc::now().to_rfc3339();

    // 3. Actualizar estado a 'revoked' y guardar timestamp y motivo
    if let Err(e) = sqlx::query(
        "UPDATE build_jobs SET status = 'revoked', revoked_at = ?, revocation_reason = ? WHERE id = ?",
    )
    .bind(&revoked_at)
    .bind(&reason_str)
    .bind(&id)
    .execute(&state.db)
    .await
    {
        tracing::error!("Error actualizando estado a revoked para {}: {:?}", id, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "database_error",
                "message": "Error al actualizar estado en base de datos"
            })),
        )
            .into_response();
    }

    // Invalida caché en memoria para que el cambio surta efecto inmediato
    state.revocation_checker.invalidate_cache().await;

    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);

    let actor = Actor::with_details(
        &user.id,
        "user",
        Some(user.username.clone()),
        Some(client_ip),
    );
    let subject = Subject::with_details(&id, "build_job", Some(role.clone()));

    let revoke_input = EventInput::new(
        trace_id,
        Source::Api,
        Category::Build,
        "build.revoked",
        actor,
        Outcome::Success,
        json!({
            "job_id": id,
            "installer_id": id,
            "role": role,
            "profile_id": profile_id,
            "reason": reason_str,
            "revoked_at": revoked_at
        }),
    )
    .with_subject(subject);

    if let Err(e) = state.audit.append(revoke_input).await {
        tracing::error!("Error emitiendo evento build.revoked: {:?}", e);
    }

    (
        StatusCode::OK,
        Json(json!({
            "id": id,
            "status": "revoked",
            "role": role,
            "profile_id": profile_id,
            "revoked_at": revoked_at,
            "reason": reason_str
        })),
    )
        .into_response()
}

/// Endpoint público/autenticado que publica la lista activa de revocaciones con soporte de caché HTTP.
pub async fn get_revocations_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    let (data, etag) = match state.revocation_checker.get_revocations().await {
        Ok(res) => res,
        Err(e) => {
            tracing::error!("Error consultando lista de revocaciones: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "database_error",
                    "message": "Fallo al consultar lista de revocaciones"
                })),
            )
                .into_response();
        }
    };

    if let Some(if_none_match) = headers.get("if-none-match").and_then(|v| v.to_str().ok()) {
        if if_none_match.trim() == etag.trim() {
            let mut res_headers = HeaderMap::new();
            res_headers.insert(
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=60"),
            );
            if let Ok(etag_val) = HeaderValue::from_str(&etag) {
                res_headers.insert("etag", etag_val);
            }
            return (StatusCode::NOT_MODIFIED, res_headers).into_response();
        }
    }

    let mut res_headers = HeaderMap::new();
    res_headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=60"),
    );
    if let Ok(etag_val) = HeaderValue::from_str(&etag) {
        res_headers.insert("etag", etag_val);
    }
    res_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    (StatusCode::OK, res_headers, Json(data)).into_response()
}

/// Revoca en lote todos los instaladores asociados a un rol (`soporte` o `tecnico`),
/// y registra la revocación global del rol.
pub async fn revoke_role_handler(
    headers: HeaderMap,
    user: AuthenticatedUser,
    State(state): State<AppState>,
    Path(role): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let client_ip = extract_client_ip(&headers, None, &state.config.trusted_proxies);
    let trace_id = extract_trace_id(&headers);

    let role_norm = role.trim().to_lowercase();
    if role_norm != "soporte" && role_norm != "tecnico" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_role",
                "message": format!("Rol '{}' no válido para revocación. Debe ser 'soporte' o 'tecnico'", role)
            })),
        )
            .into_response();
    }

    // RBAC: admin o usuario con permiso builder:revoke
    let is_admin = user.role == "admin";
    let has_revoke_perm = if !is_admin {
        let perm_row = sqlx::query(
            "SELECT 1 FROM user_permissions WHERE user_id = ? AND permission = 'builder:revoke'",
        )
        .bind(&user.id)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);
        perm_row.is_some()
    } else {
        true
    };

    if !has_revoke_perm {
        let actor = Actor::with_details(
            &user.id,
            "user",
            Some(user.username.clone()),
            Some(client_ip),
        );
        let subject = Subject::with_details(
            format!("role:{}", role_norm),
            "build_role",
            Some(role_norm.clone()),
        );
        let denied_input = EventInput::new(
            trace_id,
            Source::Api,
            Category::Auth,
            "auth.denied",
            actor,
            Outcome::Denied,
            json!({
                "error": "forbidden",
                "target_role": role_norm,
                "required_permission": "builder:revoke",
                "message": "Se requieren permisos administrativos o 'builder:revoke' para revocar un rol completo"
            }),
        )
        .with_subject(subject);
        let _ = state.audit.append(denied_input).await;

        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "forbidden",
                "message": "No tiene permisos para revocar roles de instaladores"
            })),
        )
            .into_response();
    }

    let payload: Option<RevokeBuildPayload> = if !body.is_empty() {
        serde_json::from_slice(&body).ok()
    } else {
        None
    };

    let reason_str = payload.and_then(|p| p.reason).unwrap_or_else(|| {
        format!(
            "Revocación masiva de instaladores para el rol '{}'",
            role_norm
        )
    });

    let revoked_at = Utc::now().to_rfc3339();

    // 1. Actualizar todos los jobs de ese rol a 'revoked'
    let update_res = sqlx::query(
        r#"
        UPDATE build_jobs
        SET status = 'revoked',
            revoked_at = COALESCE(revoked_at, ?),
            revocation_reason = COALESCE(revocation_reason, ?)
        WHERE role = ? AND status != 'revoked'
        "#,
    )
    .bind(&revoked_at)
    .bind(&reason_str)
    .bind(&role_norm)
    .execute(&state.db)
    .await;

    let affected_count = match update_res {
        Ok(res) => res.rows_affected(),
        Err(e) => {
            tracing::error!("Error revocando jobs de rol {}: {:?}", role_norm, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "database_error",
                    "message": "Fallo al revocar instaladores del rol"
                })),
            )
                .into_response();
        }
    };

    // 2. Insertar en tabla de roles revocados
    let role_insert = sqlx::query(
        r#"
        INSERT INTO revoked_roles (role, revoked_at, revocation_reason, revoked_by)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(role) DO UPDATE SET
            revoked_at = excluded.revoked_at,
            revocation_reason = excluded.revocation_reason,
            revoked_by = excluded.revoked_by
        "#,
    )
    .bind(&role_norm)
    .bind(&revoked_at)
    .bind(&reason_str)
    .bind(&user.id)
    .execute(&state.db)
    .await;

    if let Err(e) = role_insert {
        tracing::error!("Error registrando rol revocado en BD: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "database_error",
                "message": "Fallo al registrar revocación de rol"
            })),
        )
            .into_response();
    }

    // 3. Invalidar caché
    state.revocation_checker.invalidate_cache().await;

    // 4. Emitir auditoría build.revoked
    let actor = Actor::with_details(
        &user.id,
        "user",
        Some(user.username.clone()),
        Some(client_ip),
    );
    let subject = Subject::with_details(
        format!("role:{}", role_norm),
        "build_role",
        Some(role_norm.clone()),
    );

    let revoke_input = EventInput::new(
        trace_id,
        Source::Api,
        Category::Build,
        "build.revoked",
        actor,
        Outcome::Success,
        json!({
            "target_role": role_norm,
            "reason": reason_str,
            "affected_installers": affected_count,
            "revoked_at": revoked_at
        }),
    )
    .with_subject(subject);

    let _ = state.audit.append(revoke_input).await;

    (
        StatusCode::OK,
        Json(json!({
            "role": role_norm,
            "status": "revoked",
            "affected_installers": affected_count,
            "revoked_at": revoked_at,
            "reason": reason_str
        })),
    )
        .into_response()
}
