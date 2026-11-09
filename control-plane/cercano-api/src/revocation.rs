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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use tokio::sync::RwLock;

/// Registro de un instalador revocado individualmente.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokedInstallerItem {
    pub id: String,
    pub role: String,
    pub revoked_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Registro de un rol revocado en lote / globalmente.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokedRoleItem {
    pub role: String,
    pub revoked_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Respuesta estructurada de la lista pública/autenticada de revocaciones.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationListResponse {
    pub generated_at: String,
    pub revoked_installers: Vec<RevokedInstallerItem>,
    pub revoked_roles: Vec<RevokedRoleItem>,
}

/// Resultado de la verificación de un instalador.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationStatus {
    Valid {
        role: String,
        profile_id: String,
        expires_at: Option<String>,
    },
    InstallerRevoked {
        role: String,
        profile_id: String,
        revoked_at: String,
        reason: Option<String>,
    },
    RoleRevoked {
        role: String,
        profile_id: String,
        revoked_at: String,
        reason: Option<String>,
    },
    InstallerExpired {
        role: String,
        profile_id: String,
        expires_at: String,
    },
    NotFound,
}

#[derive(Debug, Clone)]
struct CachedRevocationData {
    cached_at: Instant,
    response: RevocationListResponse,
    revoked_installers: HashMap<String, RevokedInstallerItem>,
    revoked_roles: HashMap<String, RevokedRoleItem>,
    etag: String,
}

/// Subsistema de verificación y publicación de revocaciones y caducidades con caché en memoria.
#[derive(Clone)]
pub struct RevocationChecker {
    pool: SqlitePool,
    ttl: Duration,
    fail_closed: bool,
    cache: Arc<RwLock<Option<CachedRevocationData>>>,
}

impl RevocationChecker {
    pub fn new(pool: SqlitePool, ttl: Duration, fail_closed: bool) -> Self {
        Self {
            pool,
            ttl,
            fail_closed,
            cache: Arc::new(RwLock::new(None)),
        }
    }

    pub fn fail_closed(&self) -> bool {
        self.fail_closed
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Invalida la caché en memoria para forzar una recarga inmediata desde base de datos.
    pub async fn invalidate_cache(&self) {
        let mut lock = self.cache.write().await;
        *lock = None;
    }

    /// Obtiene la lista actual de revocaciones y su ETag. Si la caché en memoria está vigente (< TTL),
    /// se entrega de inmediato sin consultar la base de datos.
    pub async fn get_revocations(&self) -> Result<(RevocationListResponse, String), sqlx::Error> {
        {
            let lock = self.cache.read().await;
            if let Some(ref cached) = *lock {
                if cached.cached_at.elapsed() < self.ttl {
                    return Ok((cached.response.clone(), cached.etag.clone()));
                }
            }
        }

        self.refresh_cache().await
    }

    /// Recarga forzosamente las revocaciones desde la base de datos y actualiza la caché en memoria.
    pub async fn refresh_cache(&self) -> Result<(RevocationListResponse, String), sqlx::Error> {
        let rows_jobs = sqlx::query(
            r#"
            SELECT id, role, COALESCE(revoked_at, created_at) as revoked_at, revocation_reason
            FROM build_jobs
            WHERE status = 'revoked'
            ORDER BY revoked_at DESC, id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await;

        let rows_roles = sqlx::query(
            r#"
            SELECT role, revoked_at, revocation_reason
            FROM revoked_roles
            ORDER BY role ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await;

        let (rows_jobs, rows_roles) = match (rows_jobs, rows_roles) {
            (Ok(j), Ok(r)) => (j, r),
            (Err(e), _) | (_, Err(e)) => {
                if !self.fail_closed {
                    let lock = self.cache.read().await;
                    if let Some(ref cached) = *lock {
                        tracing::warn!(
                            "Error al refrescar revocaciones desde BD, usando caché previa degradada (fail-safe): {:?}",
                            e
                        );
                        return Ok((cached.response.clone(), cached.etag.clone()));
                    }
                }
                return Err(e);
            }
        };

        let mut revoked_installers = Vec::new();
        let mut installer_map = HashMap::new();

        for r in rows_jobs {
            let id: String = r.get("id");
            let role: String = r.get("role");
            let revoked_at: String = r.get("revoked_at");
            let reason: Option<String> = r.get("revocation_reason");

            let item = RevokedInstallerItem {
                id: id.clone(),
                role,
                revoked_at,
                reason,
            };
            installer_map.insert(id, item.clone());
            revoked_installers.push(item);
        }

        let mut revoked_roles = Vec::new();
        let mut role_map = HashMap::new();

        for r in rows_roles {
            let role: String = r.get("role");
            let revoked_at: String = r.get("revoked_at");
            let reason: Option<String> = r.get("revocation_reason");

            let item = RevokedRoleItem {
                role: role.clone(),
                revoked_at,
                reason,
            };
            role_map.insert(role, item.clone());
            revoked_roles.push(item);
        }

        let response = RevocationListResponse {
            generated_at: Utc::now().to_rfc3339(),
            revoked_installers,
            revoked_roles,
        };

        let mut hasher = Sha256::new();
        for item in &response.revoked_installers {
            hasher.update(item.id.as_bytes());
            hasher.update(item.role.as_bytes());
            hasher.update(item.revoked_at.as_bytes());
            if let Some(ref r) = item.reason {
                hasher.update(r.as_bytes());
            }
        }
        for item in &response.revoked_roles {
            hasher.update(item.role.as_bytes());
            hasher.update(item.revoked_at.as_bytes());
            if let Some(ref r) = item.reason {
                hasher.update(r.as_bytes());
            }
        }
        let hash_bytes = hasher.finalize();
        let etag = format!("\"{:x}\"", hash_bytes);

        let cached = CachedRevocationData {
            cached_at: Instant::now(),
            response: response.clone(),
            revoked_installers: installer_map,
            revoked_roles: role_map,
            etag: etag.clone(),
        };

        {
            let mut lock = self.cache.write().await;
            *lock = Some(cached);
        }

        Ok((response, etag))
    }

    /// Comprueba el estado de un instalador dado su ID.
    /// Valida si el instalador individual o su rol están revocados, o si ha caducado (`expires_at < now`).
    pub async fn check_installer(&self, installer_id: &str) -> Result<RevocationStatus, String> {
        let is_cache_fresh = {
            let lock = self.cache.read().await;
            lock.as_ref()
                .map(|c| c.cached_at.elapsed() < self.ttl)
                .unwrap_or(false)
        };

        if !is_cache_fresh {
            if let Err(e) = self.refresh_cache().await {
                if self.fail_closed {
                    return Err(format!(
                        "Revocation check failed contacting database (fail-closed): {}",
                        e
                    ));
                } else {
                    tracing::warn!(
                        "Revocation check refresh failed, proceeding in fail-safe mode: {}",
                        e
                    );
                }
            }
        }

        // 1. Verificar si está en la lista de revocados en memoria
        {
            let lock = self.cache.read().await;
            if let Some(ref cached) = *lock {
                if let Some(item) = cached.revoked_installers.get(installer_id) {
                    return Ok(RevocationStatus::InstallerRevoked {
                        role: item.role.clone(),
                        profile_id: String::new(),
                        revoked_at: item.revoked_at.clone(),
                        reason: item.reason.clone(),
                    });
                }
            }
        }

        // 2. Consultar datos del job/instalador en la base de datos
        let row = match sqlx::query(
            r#"
            SELECT id, role, profile_id, status, expires_at, revoked_at, revocation_reason
            FROM build_jobs
            WHERE id = ?
            "#,
        )
        .bind(installer_id)
        .fetch_optional(&self.pool)
        .await
        {
            Ok(r) => r,
            Err(e) => {
                if self.fail_closed {
                    return Err(format!(
                        "Revocation check database error (fail-closed): {}",
                        e
                    ));
                } else {
                    tracing::warn!("Revocation check database error, fail-safe allowing: {}", e);
                    return Ok(RevocationStatus::Valid {
                        role: "unknown".to_string(),
                        profile_id: "unknown".to_string(),
                        expires_at: None,
                    });
                }
            }
        };

        let row = match row {
            Some(r) => r,
            None => {
                return Ok(RevocationStatus::NotFound);
            }
        };

        let role: String = row.get("role");
        let profile_id: String = row.get("profile_id");
        let status: String = row.get("status");
        let expires_at: Option<String> = row.get("expires_at");
        let revoked_at: Option<String> = row.get("revoked_at");
        let revocation_reason: Option<String> = row.get("revocation_reason");

        // 3. Verificar status 'revoked'
        if status == "revoked" {
            return Ok(RevocationStatus::InstallerRevoked {
                role,
                profile_id,
                revoked_at: revoked_at.unwrap_or_else(|| Utc::now().to_rfc3339()),
                reason: revocation_reason,
            });
        }

        // 4. Verificar si el rol completo ha sido revocado
        {
            let lock = self.cache.read().await;
            if let Some(ref cached) = *lock {
                if let Some(role_item) = cached.revoked_roles.get(&role) {
                    return Ok(RevocationStatus::RoleRevoked {
                        role: role_item.role.clone(),
                        profile_id,
                        revoked_at: role_item.revoked_at.clone(),
                        reason: role_item.reason.clone(),
                    });
                }
            }
        }

        // 5. Verificar caducidad del instalador
        if let Some(ref exp_str) = expires_at {
            if let Ok(exp_dt) = DateTime::parse_from_rfc3339(exp_str) {
                if exp_dt.with_timezone(&Utc) < Utc::now() {
                    return Ok(RevocationStatus::InstallerExpired {
                        role,
                        profile_id,
                        expires_at: exp_str.clone(),
                    });
                }
            }
        }

        // 6. Instalador válido
        Ok(RevocationStatus::Valid {
            role,
            profile_id,
            expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::init_db;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_revocation_checker_cache_and_invalidation() {
        let pool = init_db("sqlite::memory:").await.unwrap();
        let checker = RevocationChecker::new(pool.clone(), Duration::from_secs(60), true);

        // 1. Initial state: no revocations
        let (initial, etag1) = checker.get_revocations().await.unwrap();
        assert!(initial.revoked_installers.is_empty());
        assert!(initial.revoked_roles.is_empty());

        // 2. Insert a build job and revoke it directly in db
        let job_id = Uuid::now_v7().to_string();
        sqlx::query(
            r#"
            INSERT INTO users (id, username, password_hash, role) VALUES ('u1', 'adm', 'h', 'admin');
            INSERT INTO build_jobs (id, user_id, role, profile_id, status, revoked_at, revocation_reason)
            VALUES (?, 'u1', 'soporte', 'prof-1', 'revoked', datetime('now'), 'Compromised key');
            "#,
        )
        .bind(&job_id)
        .execute(&pool)
        .await
        .unwrap();

        // 3. Since cache TTL is 60s, get_revocations should still return cached empty response
        let (cached_resp, etag_cached) = checker.get_revocations().await.unwrap();
        assert_eq!(etag1, etag_cached);
        assert!(cached_resp.revoked_installers.is_empty());

        // 4. Invalidate cache
        checker.invalidate_cache().await;

        // 5. Now it should reflect the revoked job immediately
        let (fresh_resp, etag2) = checker.get_revocations().await.unwrap();
        assert_ne!(etag1, etag2);
        assert_eq!(fresh_resp.revoked_installers.len(), 1);
        assert_eq!(fresh_resp.revoked_installers[0].id, job_id);
        assert_eq!(fresh_resp.revoked_installers[0].role, "soporte");
        assert_eq!(
            fresh_resp.revoked_installers[0].reason.as_deref(),
            Some("Compromised key")
        );

        // 6. Check installer status
        let status = checker.check_installer(&job_id).await.unwrap();
        match status {
            RevocationStatus::InstallerRevoked { role, reason, .. } => {
                assert_eq!(role, "soporte");
                assert_eq!(reason.as_deref(), Some("Compromised key"));
            }
            other => panic!("Expected InstallerRevoked, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_revocation_checker_role_revocation() {
        let pool = init_db("sqlite::memory:").await.unwrap();
        let checker = RevocationChecker::new(pool.clone(), Duration::from_secs(60), true);

        let job_id = Uuid::now_v7().to_string();
        sqlx::query(
            r#"
            INSERT INTO users (id, username, password_hash, role) VALUES ('u2', 'adm2', 'h', 'admin');
            INSERT INTO build_jobs (id, user_id, role, profile_id, status)
            VALUES (?, 'u2', 'tecnico', 'prof-tec', 'completed');
            INSERT INTO revoked_roles (role, revoked_at, revocation_reason, revoked_by)
            VALUES ('tecnico', datetime('now'), 'Global rotation', 'u2');
            "#,
        )
        .bind(&job_id)
        .execute(&pool)
        .await
        .unwrap();

        let status = checker.check_installer(&job_id).await.unwrap();
        match status {
            RevocationStatus::RoleRevoked { role, reason, .. } => {
                assert_eq!(role, "tecnico");
                assert_eq!(reason.as_deref(), Some("Global rotation"));
            }
            other => panic!("Expected RoleRevoked, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_revocation_checker_expiration() {
        let pool = init_db("sqlite::memory:").await.unwrap();
        let checker = RevocationChecker::new(pool.clone(), Duration::from_secs(60), true);

        let job_id = Uuid::now_v7().to_string();
        let expired_at = (Utc::now() - chrono::Duration::hours(2)).to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO users (id, username, password_hash, role) VALUES ('u3', 'adm3', 'h', 'admin');
            INSERT INTO build_jobs (id, user_id, role, profile_id, status, expires_at)
            VALUES (?, 'u3', 'soporte', 'prof-exp', 'completed', ?);
            "#,
        )
        .bind(&job_id)
        .bind(&expired_at)
        .execute(&pool)
        .await
        .unwrap();

        let status = checker.check_installer(&job_id).await.unwrap();
        match status {
            RevocationStatus::InstallerExpired {
                role, expires_at, ..
            } => {
                assert_eq!(role, "soporte");
                assert_eq!(expires_at, expired_at);
            }
            other => panic!("Expected InstallerExpired, got {:?}", other),
        }
    }
}
