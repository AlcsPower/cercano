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

use crate::canonical::to_canonical_json_bytes;
use crate::error::AuditError;
use crate::model::EventPayload;
use sha2::{Digest, Sha256};

/// Computes the cryptographic SHA-256 hash chaining `prev_hash` with canonical JSON payload.
///
/// Output is a 64-character lowercase hex string: `SHA256(prev_hash.as_bytes() + canonical_bytes)`.
pub fn compute_hash(prev_hash: &str, event_payload: &EventPayload) -> Result<String, AuditError> {
    let canonical_bytes = to_canonical_json_bytes(event_payload)?;
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(&canonical_bytes);
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Actor, Category, Outcome, Source, GENESIS_HASH};
    use serde_json::json;

    #[test]
    fn test_compute_hash_deterministic() {
        let payload = EventPayload {
            event_id: "0192e210-6c90-7981-9b7e-97813a30d591".to_string(),
            trace_id: "0192e210-6c90-7981-9b7e-97813a30d592".to_string(),
            ts: "2026-11-06T15:00:00.000Z".to_string(),
            source: Source::Client,
            category: Category::Conn,
            action: "conn.start".to_string(),
            actor: Actor::new("user-1"),
            subject: None,
            outcome: Outcome::Success,
            details: json!({"remote_ip": "192.168.1.50"}),
        };

        let hash1 = compute_hash(GENESIS_HASH, &payload).unwrap();
        let hash2 = compute_hash(GENESIS_HASH, &payload).unwrap();

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
        assert!(hash1
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
