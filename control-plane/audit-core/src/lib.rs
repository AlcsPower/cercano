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

//! Core append-only audit store with cryptographic hash chaining for Cercano.
//!
//! Provides deterministic RFC 8785 canonical serialization, SHA-256 hash chaining,
//! serialized database writes, and offline chain verification.

pub mod canonical;
pub mod checkpoint;
pub mod error;
pub mod export;
pub mod hash;
pub mod model;
pub mod retention;
pub mod store;

pub use canonical::{to_canonical_json_bytes, to_canonical_json_string};
pub use checkpoint::{sign_checkpoint, verify_checkpoint, AuditCheckpoint, CheckpointPayload};
pub use error::AuditError;
pub use export::{ExportConfig, ExportQueue, SyslogConfig, SyslogTransport, WebhookConfig};
pub use hash::compute_hash;
pub use model::{
    Actor, AuditEvent, Category, ChainVerificationError, EventFilter, EventInput, EventPayload,
    Outcome, Source, Subject, VerificationResult, GENESIS_HASH,
};
pub use retention::{default_retention_policies, verify_archive, ArchiveEnvelope, RetentionPolicy};
pub use store::AuditStore;
