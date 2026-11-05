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
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load().map_err(|e| format!("Configuration error: {}", e))?;

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

    let state = AppState {
        config: config.clone(),
        db,
    };

    let app = create_app(state);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let listener = TcpListener::bind(addr).await?;

    tracing::info!(address = %addr, "Listening for HTTP connections");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown::shutdown_signal())
        .await?;

    tracing::info!("Cercano API service stopped cleanly");

    Ok(())
}
