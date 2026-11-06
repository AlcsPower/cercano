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
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Canonical payload of an audit checkpoint subjected to cryptographic signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointPayload {
    pub checkpoint_id: String,
    pub sequence: i64,
    pub last_hash: String,
    pub event_count: i64,
    pub ts: String,
    pub key_id: String,
}

impl CheckpointPayload {
    pub fn new(
        checkpoint_id: impl Into<String>,
        sequence: i64,
        last_hash: impl Into<String>,
        event_count: i64,
        ts: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Self {
        Self {
            checkpoint_id: checkpoint_id.into(),
            sequence,
            last_hash: last_hash.into(),
            event_count,
            ts: ts.into(),
            key_id: key_id.into(),
        }
    }

    /// Serializes the checkpoint payload to canonical JSON bytes per RFC 8785.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, AuditError> {
        to_canonical_json_bytes(self)
    }

    /// Cryptographically signs the canonical checkpoint payload using an Ed25519 signing key.
    pub fn sign(&self, signing_key: &SigningKey) -> Result<AuditCheckpoint, AuditError> {
        let canonical_bytes = self.to_canonical_bytes()?;
        let signature = signing_key.sign(&canonical_bytes);
        let signature_hex = hex::encode(signature.to_bytes());

        Ok(AuditCheckpoint {
            checkpoint_id: self.checkpoint_id.clone(),
            sequence: self.sequence,
            last_hash: self.last_hash.clone(),
            event_count: self.event_count,
            ts: self.ts.clone(),
            key_id: self.key_id.clone(),
            signature: signature_hex,
        })
    }
}

/// Cryptographically signed checkpoint committing to a point in the audit chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCheckpoint {
    pub checkpoint_id: String,
    pub sequence: i64,
    pub last_hash: String,
    pub event_count: i64,
    pub ts: String,
    pub key_id: String,
    pub signature: String,
}

impl AuditCheckpoint {
    /// Extracts the canonical `CheckpointPayload` for signature verification.
    pub fn payload(&self) -> CheckpointPayload {
        CheckpointPayload {
            checkpoint_id: self.checkpoint_id.clone(),
            sequence: self.sequence,
            last_hash: self.last_hash.clone(),
            event_count: self.event_count,
            ts: self.ts.clone(),
            key_id: self.key_id.clone(),
        }
    }

    /// Verifies the checkpoint's Ed25519 signature against a provided public verifying key.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<bool, AuditError> {
        let sig_bytes = match hex::decode(&self.signature) {
            Ok(b) => b,
            Err(_) => return Ok(false),
        };

        let sig_array: [u8; 64] = match sig_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => return Ok(false),
        };

        let signature = Signature::from_bytes(&sig_array);
        let canonical_bytes = self.payload().to_canonical_bytes()?;

        Ok(verifying_key.verify(&canonical_bytes, &signature).is_ok())
    }
}

/// Signs a checkpoint payload using an Ed25519 signing key.
pub fn sign_checkpoint(
    signing_key: &SigningKey,
    payload: &CheckpointPayload,
) -> Result<AuditCheckpoint, AuditError> {
    payload.sign(signing_key)
}

/// Verifies a checkpoint's signature with a given Ed25519 public verifying key.
pub fn verify_checkpoint(
    verifying_key: &VerifyingKey,
    checkpoint: &AuditCheckpoint,
) -> Result<bool, AuditError> {
    checkpoint.verify(verifying_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_checkpoint_sign_and_verify() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let payload = CheckpointPayload::new(
            "0192e210-0000-7000-0000-000000000001",
            1,
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            100,
            "2026-11-06T12:00:00.000Z",
            "key-audit-2026",
        );

        let checkpoint = sign_checkpoint(&signing_key, &payload).expect("sign checkpoint");
        assert_eq!(checkpoint.sequence, 1);
        assert_eq!(checkpoint.event_count, 100);
        assert_eq!(checkpoint.signature.len(), 128); // 64 bytes in hex

        // Positive verification
        let is_valid = verify_checkpoint(&verifying_key, &checkpoint).expect("verify checkpoint");
        assert!(is_valid);

        // Verification with tampered last_hash fails
        let mut tampered = checkpoint.clone();
        tampered.last_hash =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert!(!verify_checkpoint(&verifying_key, &tampered).unwrap());

        // Verification with tampered event_count fails
        let mut tampered_count = checkpoint.clone();
        tampered_count.event_count = 101;
        assert!(!verify_checkpoint(&verifying_key, &tampered_count).unwrap());

        // Verification with forged signature fails
        let mut tampered_sig = checkpoint.clone();
        tampered_sig.signature = hex::encode([0u8; 64]);
        assert!(!verify_checkpoint(&verifying_key, &tampered_sig).unwrap());

        // Verification with different key fails
        let other_key = SigningKey::generate(&mut OsRng);
        assert!(!verify_checkpoint(&other_key.verifying_key(), &checkpoint).unwrap());
    }
}
