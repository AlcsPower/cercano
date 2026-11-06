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

use cercano_api::{config::Config, create_app, db::init_db, init_logging, shutdown, AppState};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

/// Refuses to run audit ingestion with no shared secret (an empty token would accept anyone).
fn require_internal_token(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    if config.internal_token.trim().len() < 32 {
        return Err(
            "CERCANO_INTERNAL_TOKEN must be set to a random value of at least 32 bytes".into(),
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load().map_err(|e| format!("Configuration error: {}", e))?;

    require_internal_token(&config)?;

    init_logging(&config.log_level);

    tracing::info!(
        service = "cercano-api",
        version = env!("CARGO_PKG_VERSION"),
        host = %config.host,
        port = config.port,
        database_url = %config.database_url,
        "Starting Cercano API control plane service"
    );

    let db = init_db(&config.database_url).await?;

    let audit = Arc::new(
        audit_core::AuditStore::new(db.clone())
            .await
            .map_err(|e| format!("Failed to initialize AuditStore: {}", e))?,
    );

    // Signed checkpoints are what make a rewrite of the chain detectable offline.
    let audit_key_path = config.audit_key_path.clone();
    let audit_key = Arc::new(
        cercano_api::server_keys::load_or_create_audit_signing_key(&audit_key_path)
            .map_err(|e| format!("Failed to load audit signing key: {}", e))?,
    );
    tracing::info!(path = %audit_key_path, "Audit checkpoint signing key loaded");

    let checkpoint_interval = config.audit_checkpoint_interval_secs.max(10);
    let checkpoint_audit = audit.clone();
    let checkpoint_key = audit_key.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(checkpoint_interval));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await; // discard the immediate first tick
        loop {
            ticker.tick().await;
            let last_event = match checkpoint_audit.get_last_event().await {
                Ok(event) => event,
                Err(err) => {
                    tracing::warn!(error = %err, "Audit checkpoint skipped: cannot read chain head");
                    continue;
                }
            };
            let Some(last) = last_event else { continue };
            let already_signed = checkpoint_audit
                .get_last_checkpoint()
                .await
                .ok()
                .flatten()
                .is_some_and(|checkpoint| checkpoint.event_count >= last.sequence);
            if already_signed {
                continue;
            }
            match checkpoint_audit
                .create_checkpoint(&checkpoint_key, "audit-ed25519-1")
                .await
            {
                Ok(checkpoint) => tracing::info!(
                    sequence = checkpoint.sequence,
                    event_count = checkpoint.event_count,
                    "Audit checkpoint created"
                ),
                Err(err) => tracing::error!(error = %err, "Audit checkpoint failed"),
            }
        }
    });

    let state = AppState::new(config.clone(), db, audit);

    let app = create_app(state);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let listener = TcpListener::bind(addr).await?;

    tracing::info!(address = %addr, "Listening for HTTP connections");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown::shutdown_signal())
    .await?;

    tracing::info!("Cercano API service stopped cleanly");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_token_is_required_and_long_enough() {
        let mut config = Config::default();
        assert!(require_internal_token(&config).is_err());

        config.internal_token = "short".to_string();
        assert!(require_internal_token(&config).is_err());

        config.internal_token = "a".repeat(32);
        assert!(require_internal_token(&config).is_ok());
    }
}
