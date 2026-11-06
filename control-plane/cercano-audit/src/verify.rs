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

use audit_core::{compute_hash, verify_checkpoint, AuditCheckpoint, AuditEvent, GENESIS_HASH};
use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

/// Summary result of verifying an audit file stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationSummary {
    pub is_valid: bool,
    pub total_events: usize,
    pub total_checkpoints: usize,
    pub first_sequence: Option<i64>,
    pub last_sequence: Option<i64>,
    pub signatures_verified: bool,
    pub error_sequence: Option<i64>,
    pub error_message: Option<String>,
}

/// Loads an Ed25519 verifying key from either a 64-character hex string or a file path (.pub).
pub fn load_verifying_key(input: &str) -> Result<VerifyingKey, String> {
    let path = Path::new(input);
    if path.is_file() {
        // Read file contents
        let raw_bytes = std::fs::read(path)
            .map_err(|e| format!("Failed to read pubkey file '{}': {}", input, e))?;

        if let Ok(text) = std::str::from_utf8(&raw_bytes) {
            let trimmed = text.trim();
            if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                let bytes = hex::decode(trimmed)
                    .map_err(|e| format!("Invalid hex in pubkey file: {}", e))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| "Invalid key length".to_string())?;
                return VerifyingKey::from_bytes(&arr)
                    .map_err(|e| format!("Invalid Ed25519 public key: {}", e));
            }
        }

        // Try raw 32 bytes binary
        if raw_bytes.len() == 32 {
            let arr: [u8; 32] = raw_bytes.try_into().unwrap();
            return VerifyingKey::from_bytes(&arr)
                .map_err(|e| format!("Invalid Ed25519 public key: {}", e));
        }

        return Err(format!(
            "Pubkey file '{}' must contain 64 hex characters or 32 raw bytes (got {} bytes)",
            input,
            raw_bytes.len()
        ));
    }

    // Direct hex string on CLI
    let trimmed = input.trim();
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes =
            hex::decode(trimmed).map_err(|e| format!("Invalid hex in pubkey string: {}", e))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "Invalid key length".to_string())?;
        VerifyingKey::from_bytes(&arr).map_err(|e| format!("Invalid Ed25519 public key: {}", e))
    } else {
        Err(format!(
            "Pubkey must be a 64-character hex string or path to an existing file (got input '{}')",
            input
        ))
    }
}

/// Verifies a JSONL stream of audit events and checkpoints.
pub fn verify_file(
    file_path: &Path,
    verifying_key: Option<&VerifyingKey>,
    verbose: bool,
) -> Result<VerificationSummary, Box<dyn std::error::Error + Send + Sync>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);

    let mut total_events = 0usize;
    let mut total_checkpoints = 0usize;
    let mut expected_event_seq = 1i64;
    let mut expected_cp_seq = 1i64;
    let mut current_prev_hash = GENESIS_HASH.to_string();
    let mut first_event_seq: Option<i64> = None;
    let mut last_event_seq: Option<i64> = None;
    let mut map_seq_to_hash: HashMap<i64, String> = HashMap::new();

    for (line_idx, line_res) in reader.lines().enumerate() {
        let line_num = line_idx + 1;
        let line = line_res?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let val: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                return Ok(VerificationSummary {
                    is_valid: false,
                    total_events,
                    total_checkpoints,
                    first_sequence: first_event_seq,
                    last_sequence: last_event_seq,
                    signatures_verified: verifying_key.is_some() && total_checkpoints > 0,
                    error_sequence: Some(line_num as i64),
                    error_message: Some(format!("Malformed JSON at line {}: {}", line_num, e)),
                });
            }
        };

        let typ = val.get("type").and_then(|v| v.as_str());

        let is_checkpoint = match typ {
            Some("checkpoint") => true,
            Some("event") => false,
            _ => val.get("checkpoint_id").is_some(),
        };

        if is_checkpoint {
            let cp_res: Result<AuditCheckpoint, _> = if let Some(data) = val.get("data") {
                serde_json::from_value(data.clone())
            } else {
                serde_json::from_value(val.clone())
            };

            let cp = match cp_res {
                Ok(c) => c,
                Err(e) => {
                    return Ok(VerificationSummary {
                        is_valid: false,
                        total_events,
                        total_checkpoints,
                        first_sequence: first_event_seq,
                        last_sequence: last_event_seq,
                        signatures_verified: verifying_key.is_some() && total_checkpoints > 0,
                        error_sequence: Some(line_num as i64),
                        error_message: Some(format!(
                            "Failed to parse checkpoint at line {}: {}",
                            line_num, e
                        )),
                    });
                }
            };

            // 1. Checkpoint sequence continuity
            if cp.sequence != expected_cp_seq {
                return Ok(VerificationSummary {
                    is_valid: false,
                    total_events,
                    total_checkpoints,
                    first_sequence: first_event_seq,
                    last_sequence: last_event_seq,
                    signatures_verified: verifying_key.is_some() && total_checkpoints > 0,
                    error_sequence: Some(cp.sequence),
                    error_message: Some(format!(
                        "Checkpoint sequence gap: expected {}, found {}",
                        expected_cp_seq, cp.sequence
                    )),
                });
            }

            // 2. Checkpoint alignment
            if cp.event_count == 0 {
                if cp.last_hash != GENESIS_HASH {
                    return Ok(VerificationSummary {
                        is_valid: false,
                        total_events,
                        total_checkpoints,
                        first_sequence: first_event_seq,
                        last_sequence: last_event_seq,
                        signatures_verified: verifying_key.is_some() && total_checkpoints > 0,
                        error_sequence: Some(cp.sequence),
                        error_message: Some(format!(
                            "Checkpoint #{} alignment error: event_count is 0 but last_hash is '{}', expected genesis hash '{}'",
                            cp.sequence, cp.last_hash, GENESIS_HASH
                        )),
                    });
                }
            } else {
                let highest_seen = last_event_seq.unwrap_or(0);
                if cp.event_count > highest_seen {
                    return Ok(VerificationSummary {
                        is_valid: false,
                        total_events,
                        total_checkpoints,
                        first_sequence: first_event_seq,
                        last_sequence: last_event_seq,
                        signatures_verified: verifying_key.is_some() && total_checkpoints > 0,
                        error_sequence: Some(cp.sequence),
                        error_message: Some(format!(
                            "Checkpoint #{} references future event sequence {} (highest seen: {})",
                            cp.sequence, cp.event_count, highest_seen
                        )),
                    });
                }

                match map_seq_to_hash.get(&cp.event_count) {
                    Some(recorded_hash) if recorded_hash == &cp.last_hash => {}
                    Some(recorded_hash) => {
                        return Ok(VerificationSummary {
                            is_valid: false,
                            total_events,
                            total_checkpoints,
                            first_sequence: first_event_seq,
                            last_sequence: last_event_seq,
                            signatures_verified: verifying_key.is_some() && total_checkpoints > 0,
                            error_sequence: Some(cp.event_count),
                            error_message: Some(format!(
                                "Checkpoint #{} last_hash '{}' does not match event sequence {} hash '{}'",
                                cp.sequence, cp.last_hash, cp.event_count, recorded_hash
                            )),
                        });
                    }
                    None => {
                        return Ok(VerificationSummary {
                            is_valid: false,
                            total_events,
                            total_checkpoints,
                            first_sequence: first_event_seq,
                            last_sequence: last_event_seq,
                            signatures_verified: verifying_key.is_some() && total_checkpoints > 0,
                            error_sequence: Some(cp.event_count),
                            error_message: Some(format!(
                                "Checkpoint #{} references missing event sequence {}",
                                cp.sequence, cp.event_count
                            )),
                        });
                    }
                }
            }

            // 3. Signature verification (if public key supplied)
            if let Some(vk) = verifying_key {
                match verify_checkpoint(vk, &cp) {
                    Ok(true) => {}
                    _ => {
                        return Ok(VerificationSummary {
                            is_valid: false,
                            total_events,
                            total_checkpoints,
                            first_sequence: first_event_seq,
                            last_sequence: last_event_seq,
                            signatures_verified: false,
                            error_sequence: Some(cp.sequence),
                            error_message: Some(format!(
                                "Checkpoint #{} (id: {}) signature verification failed for key_id '{}'",
                                cp.sequence, cp.checkpoint_id, cp.key_id
                            )),
                        });
                    }
                }
            }

            if verbose {
                println!(
                    "[OK] Checkpoint #{}: id={}, events={}, key_id={}, sig={}..{}",
                    cp.sequence,
                    cp.checkpoint_id,
                    cp.event_count,
                    cp.key_id,
                    &cp.signature[..8.min(cp.signature.len())],
                    &cp.signature[cp.signature.len().saturating_sub(8)..]
                );
            }

            expected_cp_seq = cp.sequence + 1;
            total_checkpoints += 1;
        } else {
            // Event
            let ev_res: Result<AuditEvent, _> = if let Some(data) = val.get("data") {
                serde_json::from_value(data.clone())
            } else {
                serde_json::from_value(val.clone())
            };

            let ev = match ev_res {
                Ok(e) => e,
                Err(e) => {
                    return Ok(VerificationSummary {
                        is_valid: false,
                        total_events,
                        total_checkpoints,
                        first_sequence: first_event_seq,
                        last_sequence: last_event_seq,
                        signatures_verified: verifying_key.is_some() && total_checkpoints > 0,
                        error_sequence: Some(line_num as i64),
                        error_message: Some(format!(
                            "Failed to parse audit event at line {}: {}",
                            line_num, e
                        )),
                    });
                }
            };

            // 1. Sequence continuity
            if first_event_seq.is_none() {
                if ev.sequence != 1 {
                    return Ok(VerificationSummary {
                        is_valid: false,
                        total_events,
                        total_checkpoints,
                        first_sequence: Some(ev.sequence),
                        last_sequence: last_event_seq,
                        signatures_verified: verifying_key.is_some() && total_checkpoints > 0,
                        error_sequence: Some(ev.sequence),
                        error_message: Some(format!(
                            "Sequence gap at stream start: expected sequence 1, found {}",
                            ev.sequence
                        )),
                    });
                }
                first_event_seq = Some(ev.sequence);
            } else if ev.sequence != expected_event_seq {
                return Ok(VerificationSummary {
                    is_valid: false,
                    total_events,
                    total_checkpoints,
                    first_sequence: first_event_seq,
                    last_sequence: last_event_seq,
                    signatures_verified: verifying_key.is_some() && total_checkpoints > 0,
                    error_sequence: Some(ev.sequence),
                    error_message: Some(format!(
                        "Sequence gap detected: expected {}, found {}",
                        expected_event_seq, ev.sequence
                    )),
                });
            }

            // 2. Hash chaining link
            if ev.prev_hash != current_prev_hash {
                return Ok(VerificationSummary {
                    is_valid: false,
                    total_events,
                    total_checkpoints,
                    first_sequence: first_event_seq,
                    last_sequence: last_event_seq,
                    signatures_verified: verifying_key.is_some() && total_checkpoints > 0,
                    error_sequence: Some(ev.sequence),
                    error_message: Some(format!(
                        "Chain link broken at sequence {}: prev_hash '{}' does not match previous hash '{}'",
                        ev.sequence, ev.prev_hash, current_prev_hash
                    )),
                });
            }

            // 3. Cryptographic hash computation
            let computed_hash = compute_hash(&ev.prev_hash, &ev.payload()).map_err(|e| {
                format!("Failed to compute hash for sequence {}: {}", ev.sequence, e)
            })?;

            if ev.hash != computed_hash {
                return Ok(VerificationSummary {
                    is_valid: false,
                    total_events,
                    total_checkpoints,
                    first_sequence: first_event_seq,
                    last_sequence: last_event_seq,
                    signatures_verified: verifying_key.is_some() && total_checkpoints > 0,
                    error_sequence: Some(ev.sequence),
                    error_message: Some(format!(
                        "Hash mismatch at sequence {}: computed '{}', recorded '{}'",
                        ev.sequence, computed_hash, ev.hash
                    )),
                });
            }

            if verbose {
                println!(
                    "[OK] Event #{}: id={}, action={}, hash={}..{}",
                    ev.sequence,
                    ev.event_id,
                    ev.action,
                    &ev.hash[..8.min(ev.hash.len())],
                    &ev.hash[ev.hash.len().saturating_sub(8)..]
                );
            }

            current_prev_hash = ev.hash.clone();
            map_seq_to_hash.insert(ev.sequence, ev.hash.clone());
            expected_event_seq = ev.sequence + 1;
            last_event_seq = Some(ev.sequence);
            total_events += 1;
        }
    }

    Ok(VerificationSummary {
        is_valid: true,
        total_events,
        total_checkpoints,
        first_sequence: first_event_seq,
        last_sequence: last_event_seq,
        signatures_verified: verifying_key.is_some() && total_checkpoints > 0,
        error_sequence: None,
        error_message: None,
    })
}

/// Formats and prints a verification summary to a given writer.
pub fn print_summary(summary: &VerificationSummary, out: &mut impl Write) -> std::io::Result<()> {
    writeln!(out, "==================================================")?;
    writeln!(out, "           AUDIT VERIFICATION SUMMARY             ")?;
    writeln!(out, "==================================================")?;
    if summary.is_valid {
        writeln!(out, "Status:             VALID")?;
    } else {
        writeln!(out, "Status:             CORRUPTED")?;
        if let Some(seq) = summary.error_sequence {
            writeln!(out, "Failed Sequence:    {}", seq)?;
        }
        if let Some(ref err) = summary.error_message {
            writeln!(out, "Failure Details:    {}", err)?;
        }
    }
    writeln!(out, "Total Events:       {}", summary.total_events)?;
    writeln!(out, "Total Checkpoints:  {}", summary.total_checkpoints)?;
    match (summary.first_sequence, summary.last_sequence) {
        (Some(first), Some(last)) => writeln!(out, "Verified Range:     [{}..{}]", first, last)?,
        _ => writeln!(out, "Verified Range:     None")?,
    }
    if summary.signatures_verified {
        writeln!(out, "Signatures:         VERIFIED (Ed25519)")?;
    } else if summary.total_checkpoints > 0 {
        writeln!(
            out,
            "Signatures:         UNVERIFIED (no public key supplied)"
        )?;
    } else {
        writeln!(out, "Signatures:         N/A (no checkpoints present)")?;
    }
    writeln!(out, "==================================================")?;
    Ok(())
}
