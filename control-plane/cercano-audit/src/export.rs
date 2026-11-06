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

use audit_core::{AuditStore, EventFilter};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

/// Exports an SQLite audit database to a verifiable JSONL file.
pub async fn export_database(
    db_path: &Path,
    output_path: &Path,
) -> Result<(usize, usize), Box<dyn std::error::Error + Send + Sync>> {
    let db_str = db_path.to_string_lossy().to_string();
    let url = if db_str.starts_with("sqlite:") {
        db_str
    } else {
        format!("sqlite://{}", db_path.display())
    };

    let store = AuditStore::open_url(&url).await?;
    let events = store.query_events(EventFilter::default()).await?;
    let checkpoints = store.list_checkpoints(None).await?;

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let file = File::create(output_path)?;
    let mut writer = BufWriter::new(file);

    let mut cp_idx = 0;

    // 1. Write checkpoints with event_count == 0 first
    while cp_idx < checkpoints.len() && checkpoints[cp_idx].event_count == 0 {
        let mut val = serde_json::to_value(&checkpoints[cp_idx])?;
        if let Some(obj) = val.as_object_mut() {
            obj.insert(
                "type".to_string(),
                serde_json::Value::String("checkpoint".to_string()),
            );
        }
        serde_json::to_writer(&mut writer, &val)?;
        writer.write_all(b"\n")?;
        cp_idx += 1;
    }

    // 2. Write events and matching checkpoints
    for event in &events {
        let mut val = serde_json::to_value(event)?;
        if let Some(obj) = val.as_object_mut() {
            obj.insert(
                "type".to_string(),
                serde_json::Value::String("event".to_string()),
            );
        }
        serde_json::to_writer(&mut writer, &val)?;
        writer.write_all(b"\n")?;

        while cp_idx < checkpoints.len() && checkpoints[cp_idx].event_count == event.sequence {
            let mut cp_val = serde_json::to_value(&checkpoints[cp_idx])?;
            if let Some(obj) = cp_val.as_object_mut() {
                obj.insert(
                    "type".to_string(),
                    serde_json::Value::String("checkpoint".to_string()),
                );
            }
            serde_json::to_writer(&mut writer, &cp_val)?;
            writer.write_all(b"\n")?;
            cp_idx += 1;
        }
    }

    // 3. Write any remaining checkpoints
    while cp_idx < checkpoints.len() {
        let mut val = serde_json::to_value(&checkpoints[cp_idx])?;
        if let Some(obj) = val.as_object_mut() {
            obj.insert(
                "type".to_string(),
                serde_json::Value::String("checkpoint".to_string()),
            );
        }
        serde_json::to_writer(&mut writer, &val)?;
        writer.write_all(b"\n")?;
        cp_idx += 1;
    }

    writer.flush()?;
    Ok((events.len(), checkpoints.len()))
}
