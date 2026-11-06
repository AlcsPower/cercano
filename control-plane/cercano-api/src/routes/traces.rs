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

use std::collections::HashSet;

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use audit_core::{Actor, EventFilter, Subject};

use crate::auth::AuthenticatedUser;
use crate::routes::audit::{require_admin, AuditRouteError};
use crate::AppState;

/// Summary metrics computed across an aggregated session timeline.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SessionMetrics {
    pub duration_seconds: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub total_bytes: u64,
    pub file_count: usize,
    pub packet_count: u64,
    pub event_count: usize,
    pub alarm_count: usize,
}

/// A single discrete event entry positioned chronologically in the session timeline.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TimelineItem {
    pub sequence: i64,
    pub event_id: String,
    pub trace_id: String,
    pub ts: String,
    pub source: String,
    pub category: String,
    pub action: String,
    pub actor: Actor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<Subject>,
    pub outcome: String,
    pub details: serde_json::Value,
    pub hash: String,
    pub correlation_method: String,
}

/// Comprehensive overview and timeline representation of a correlated session.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TraceSessionResponse {
    pub trace_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub two_factor_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_direct_lan: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    pub duration_seconds: u64,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<Actor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controlled: Option<Subject>,
    pub metrics: SessionMetrics,
    pub timeline: Vec<TimelineItem>,
}

fn parse_ts(ts: &str) -> chrono::DateTime<chrono::Utc> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
        return dt.with_timezone(&chrono::Utc);
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S") {
        return chrono::DateTime::from_naive_utc_and_offset(naive, chrono::Utc);
    }
    chrono::Utc::now()
}

/// Assembles a deterministic session timeline and metrics from direct and fallback-correlated events.
pub async fn assemble_session_trace(
    trace_id: &str,
    state: &AppState,
) -> Result<Option<TraceSessionResponse>, AuditRouteError> {
    // 1. Fetch direct events by trace_id
    let filter = EventFilter {
        trace_id: Some(trace_id.to_string()),
        ..Default::default()
    };
    let direct_events = state.audit.query_events(filter).await?;

    if direct_events.is_empty() {
        return Ok(None);
    }

    // 2. Identify session participants and time window from direct events
    let conn_start = direct_events.iter().find(|e| e.action == "conn.start");
    let conn_end = direct_events.iter().find(|e| e.action == "conn.end");

    let controller_id = conn_start
        .map(|e| e.actor.id.clone())
        .or_else(|| direct_events.first().map(|e| e.actor.id.clone()));

    let controlled_id = conn_start
        .and_then(|e| e.subject.as_ref().map(|s| s.id.clone()))
        .or_else(|| {
            direct_events
                .first()
                .and_then(|e| e.subject.as_ref().map(|s| s.id.clone()))
        });

    let started_at = conn_start
        .map(|e| e.ts.clone())
        .or_else(|| direct_events.first().map(|e| e.ts.clone()));

    let start_dt = started_at
        .as_deref()
        .map(parse_ts)
        .unwrap_or_else(chrono::Utc::now);

    let ended_at = conn_end.map(|e| e.ts.clone());
    let end_dt = ended_at.as_deref().map(parse_ts);

    // 3. Fallback correlation:
    // If an event lacks a trace_id (empty/unknown/none) but matches (controller_id, controlled_id)
    // within a +/- 5 minute window of the session, link it deterministically.
    let mut fallback_events = Vec::new();
    if let (Some(ctrl_id), Some(tgt_id)) = (&controller_id, &controlled_id) {
        let win_start = start_dt - chrono::Duration::minutes(5);
        let win_end = if let Some(e_dt) = end_dt {
            e_dt + chrono::Duration::minutes(5)
        } else {
            let last_dt = direct_events
                .last()
                .map(|e| parse_ts(&e.ts))
                .unwrap_or_else(chrono::Utc::now);
            std::cmp::max(last_dt, chrono::Utc::now()) + chrono::Duration::minutes(5)
        };

        let win_start_str = win_start.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let win_end_str = win_end.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        fallback_events = state
            .audit
            .query_unlinked_events(ctrl_id, tgt_id, &win_start_str, &win_end_str)
            .await?;
    }

    // 4. Build timeline
    let mut seen_ids = HashSet::new();
    let mut timeline = Vec::new();

    for ev in &direct_events {
        seen_ids.insert(ev.event_id.clone());
        timeline.push(TimelineItem {
            sequence: ev.sequence,
            event_id: ev.event_id.clone(),
            trace_id: ev.trace_id.clone(),
            ts: ev.ts.clone(),
            source: ev.source.as_str().to_string(),
            category: ev.category.as_str().to_string(),
            action: ev.action.clone(),
            actor: ev.actor.clone(),
            subject: ev.subject.clone(),
            outcome: ev.outcome.as_str().to_string(),
            details: ev.details.clone(),
            hash: ev.hash.clone(),
            correlation_method: "trace_id".to_string(),
        });
    }

    for ev in fallback_events {
        if seen_ids.insert(ev.event_id.clone()) {
            timeline.push(TimelineItem {
                sequence: ev.sequence,
                event_id: ev.event_id,
                trace_id: ev.trace_id,
                ts: ev.ts,
                source: ev.source.as_str().to_string(),
                category: ev.category.as_str().to_string(),
                action: ev.action,
                actor: ev.actor,
                subject: ev.subject,
                outcome: ev.outcome.as_str().to_string(),
                details: ev.details,
                hash: ev.hash,
                correlation_method: "fallback_window".to_string(),
            });
        }
    }

    // Sort chronologically (primary: ts ASC, secondary: sequence ASC)
    timeline.sort_by(|a, b| a.ts.cmp(&b.ts).then_with(|| a.sequence.cmp(&b.sequence)));

    // 5. Compute metrics & state
    let status = if conn_end.is_some() {
        "completed".to_string()
    } else {
        "active".to_string()
    };

    let session_type = conn_start.and_then(|e| {
        e.details
            .get("session_type")
            .and_then(|v| v.as_str())
            .map(String::from)
    });
    let auth_method = conn_start.and_then(|e| {
        e.details
            .get("auth_method")
            .and_then(|v| v.as_str())
            .map(String::from)
    });
    let two_factor_verified = conn_start.and_then(|e| {
        e.details
            .get("two_factor_verified")
            .and_then(|v| v.as_bool())
    });
    let is_direct_lan =
        conn_start.and_then(|e| e.details.get("is_direct_lan").and_then(|v| v.as_bool()));

    let close_reason = conn_end.and_then(|e| {
        e.details
            .get("close_reason")
            .and_then(|v| v.as_str())
            .map(String::from)
    });
    let session_notes = conn_end.and_then(|e| {
        e.details
            .get("session_notes")
            .and_then(|v| v.as_str())
            .map(String::from)
    });

    // Duration calculation
    let recorded_duration =
        conn_end.and_then(|e| e.details.get("duration_seconds").and_then(|v| v.as_u64()));
    let duration_seconds = if let Some(d) = recorded_duration {
        d
    } else if let Some(e_dt) = end_dt {
        (e_dt - start_dt).num_seconds().max(0) as u64
    } else {
        (chrono::Utc::now() - start_dt).num_seconds().max(0) as u64
    };

    // Bytes calculation
    let conn_end_sent = conn_end
        .and_then(|e| e.details.get("bytes_sent").and_then(|v| v.as_u64()))
        .unwrap_or(0);
    let conn_end_recv = conn_end
        .and_then(|e| e.details.get("bytes_received").and_then(|v| v.as_u64()))
        .unwrap_or(0);

    let mut file_upload_bytes = 0u64;
    let mut file_download_bytes = 0u64;
    let mut file_count = 0usize;
    let mut packet_count = 0u64;
    let mut alarm_count = 0usize;
    let mut has_failure = false;
    let mut has_denied = false;

    for item in &timeline {
        if item.category == "file" || item.action == "file.transfer" {
            file_count += 1;
            let b = item
                .details
                .get("bytes_transferred")
                .or_else(|| item.details.get("bytes"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let dir = item
                .details
                .get("direction")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if dir == "upload" {
                file_upload_bytes += b;
            } else if dir == "download" {
                file_download_bytes += b;
            }
        }

        if item.category == "alarm" || item.action.starts_with("alarm.") {
            alarm_count += 1;
        }

        if let Some(p) = item
            .details
            .get("packet_count")
            .or_else(|| item.details.get("packets"))
            .and_then(|v| v.as_u64())
        {
            packet_count += p;
        }

        if item.outcome == "failure" {
            has_failure = true;
        } else if item.outcome == "denied" {
            has_denied = true;
        }
    }

    let bytes_sent = if conn_end_sent > 0 {
        conn_end_sent
    } else {
        file_upload_bytes
    };
    let bytes_received = if conn_end_recv > 0 {
        conn_end_recv
    } else {
        file_download_bytes
    };
    let total_bytes = bytes_sent + bytes_received;

    let outcome = if has_denied {
        "denied".to_string()
    } else if has_failure {
        "failure".to_string()
    } else if let Some(end) = conn_end {
        end.outcome.as_str().to_string()
    } else {
        "active".to_string()
    };

    let controller = conn_start
        .map(|e| e.actor.clone())
        .or_else(|| timeline.first().map(|e| e.actor.clone()));
    let controlled = conn_start
        .and_then(|e| e.subject.clone())
        .or_else(|| timeline.first().and_then(|e| e.subject.clone()));

    let metrics = SessionMetrics {
        duration_seconds,
        bytes_sent,
        bytes_received,
        total_bytes,
        file_count,
        packet_count,
        event_count: timeline.len(),
        alarm_count,
    };

    Ok(Some(TraceSessionResponse {
        trace_id: trace_id.to_string(),
        status,
        session_type,
        auth_method,
        two_factor_verified,
        is_direct_lan,
        started_at,
        ended_at,
        duration_seconds,
        outcome,
        close_reason,
        session_notes,
        controller,
        controlled,
        metrics,
        timeline,
    }))
}

/// `GET /api/audit/traces/:trace_id`
///
/// Fetches the complete correlated session overview, participant details, computed metrics,
/// and chronologically aggregated timeline for a specific `trace_id`.
/// Protected by Admin Bearer token.
pub async fn get_trace_timeline_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(trace_id): Path<String>,
) -> Result<Json<TraceSessionResponse>, AuditRouteError> {
    require_admin(&user)?;

    let overview = assemble_session_trace(&trace_id, &state).await?;

    match overview {
        Some(response) => Ok(Json(response)),
        None => Err(AuditRouteError::NotFound(format!(
            "Trace '{}' no encontrado",
            trace_id
        ))),
    }
}
