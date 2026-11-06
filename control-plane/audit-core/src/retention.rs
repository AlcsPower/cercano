// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

//! Retention, signed compressed archives, and controlled purge.
use crate::{Actor, AuditError, AuditEvent, AuditStore, Category, EventInput, Outcome, Source};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub category: Category,
    pub retention_days: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveEnvelope {
    pub format: u32,
    pub first_sequence: i64,
    pub last_sequence: i64,
    pub head_hash: String,
    pub events: Vec<AuditEvent>,
    pub archive_sha256: String,
    pub key_id: String,
    pub signature: String,
}
impl RetentionPolicy {
    pub fn new(category: Category, retention_days: i64) -> Result<Self, AuditError> {
        if retention_days < 1 {
            return Err(AuditError::InvalidInput(
                "retention_days must be positive".into(),
            ));
        }
        Ok(Self {
            category,
            retention_days,
        })
    }
}
pub fn default_retention_policies() -> Vec<RetentionPolicy> {
    vec![
        RetentionPolicy::new(Category::Conn, 365).unwrap(),
        RetentionPolicy::new(Category::Console, 1095).unwrap(),
    ]
}
fn archive_payload(envelope: &ArchiveEnvelope) -> Result<Vec<u8>, AuditError> {
    let mut copy = envelope.clone();
    copy.archive_sha256.clear();
    copy.signature.clear();
    crate::to_canonical_json_bytes(&copy)
}
pub fn verify_archive(
    path: impl AsRef<Path>,
    verifying_key: &VerifyingKey,
) -> Result<ArchiveEnvelope, AuditError> {
    let bytes = std::fs::read(path)?;
    let mut decoder = GzDecoder::new(bytes.as_slice());
    let mut json = Vec::new();
    decoder.read_to_end(&mut json)?;
    let envelope: ArchiveEnvelope = serde_json::from_slice(&json)?;
    let payload = archive_payload(&envelope)?;
    if hex::encode(Sha256::digest(&payload)) != envelope.archive_sha256 {
        return Err(AuditError::CheckpointVerification(
            "archive digest mismatch".into(),
        ));
    }
    let sig = Signature::from_slice(&hex::decode(&envelope.signature)?)
        .map_err(|e| AuditError::Signature(e.to_string()))?;
    verifying_key
        .verify(&payload, &sig)
        .map_err(|e| AuditError::Signature(e.to_string()))?;
    Ok(envelope)
}
impl AuditStore {
    pub async fn archive_before(
        &self,
        cutoff: DateTime<Utc>,
        path: impl AsRef<Path>,
        signing_key: &SigningKey,
        key_id: &str,
    ) -> Result<Option<ArchiveEnvelope>, AuditError> {
        const ARCHIVE_PAGE_SIZE: i64 = 10_000;
        // Pages bound database fetches; the signed envelope remains one file for compatibility.
        let mut events = Vec::new();
        let mut offset = 0;
        loop {
            let page = self
                .query_events(crate::model::EventFilter {
                    to_ts: Some(cutoff.to_rfc3339()),
                    limit: Some(ARCHIVE_PAGE_SIZE),
                    offset: Some(offset),
                    ..Default::default()
                })
                .await?;
            let done = page.len() < ARCHIVE_PAGE_SIZE as usize;
            events.extend(page);
            if done {
                break;
            }
            offset += ARCHIVE_PAGE_SIZE;
        }
        if events.is_empty() {
            return Ok(None);
        }
        let payload = ArchiveEnvelope {
            format: 1,
            first_sequence: events[0].sequence,
            last_sequence: events[events.len() - 1].sequence,
            head_hash: events.last().unwrap().hash.clone(),
            events,
            archive_sha256: String::new(),
            key_id: key_id.into(),
            signature: String::new(),
        };
        let mut envelope = payload.clone();
        let bytes = archive_payload(&payload)?;
        envelope.archive_sha256 = hex::encode(Sha256::digest(&bytes));
        envelope.signature = hex::encode(signing_key.sign(&bytes).to_bytes());
        let json = serde_json::to_vec(&envelope)?;
        let file = std::fs::File::create(path)?;
        let mut encoder = GzEncoder::new(file, Compression::default());
        encoder.write_all(&json)?;
        encoder.finish()?;
        Ok(Some(envelope))
    }
    pub async fn purge_before(&self, cutoff: DateTime<Utc>) -> Result<u64, AuditError> {
        // Physical deletion requires a verified chain truncation checkpoint; this records
        // the approval request only, so the audit event must not claim a purge happened.
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE ts < ? AND action <> 'retention.purge_approved'",
        )
        .bind(cutoff.to_rfc3339())
        .fetch_one(self.pool())
        .await?;
        if count == 0 {
            return Ok(0);
        }
        let event = self.append(EventInput { trace_id: "audit-retention".into(), source: Source::Api, category: Category::Other("audit".into()), action: "retention.purge_approved".into(), actor: Actor::new("system"), subject: None, outcome: Outcome::Success, details: serde_json::json!({"cutoff": cutoff.to_rfc3339(), "eligible_events": count, "executed": false}), event_id: None, ts: None }).await?;
        let _ = event;
        Ok(count as u64)
    }
}
