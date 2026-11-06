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

use crate::error::AuditError;
use serde::Serialize;
use serde_json::Value;
use std::io::Write;

/// Canonicalizes a JSON value into a writer per RFC 8785 (JSON Canonicalization Scheme).
///
/// Rules:
/// - Whitespace is strictly eliminated (no space after `:`, `,`, etc.).
/// - Object keys are sorted lexicographically by UTF-8 bytes.
/// - Strings and characters are JSON-escaped canonically.
/// - Numbers and booleans maintain standard minimal formatting.
pub fn canonicalize_to_writer<W: Write>(value: &Value, writer: &mut W) -> Result<(), AuditError> {
    match value {
        Value::Null => {
            writer.write_all(b"null")?;
        }
        Value::Bool(b) => {
            if *b {
                writer.write_all(b"true")?;
            } else {
                writer.write_all(b"false")?;
            }
        }
        Value::Number(n) => {
            writer.write_all(n.to_string().as_bytes())?;
        }
        Value::String(s) => {
            serde_json::to_writer(&mut *writer, s)?;
        }
        Value::Array(arr) => {
            writer.write_all(b"[")?;
            for (i, elem) in arr.iter().enumerate() {
                if i > 0 {
                    writer.write_all(b",")?;
                }
                canonicalize_to_writer(elem, writer)?;
            }
            writer.write_all(b"]")?;
        }
        Value::Object(map) => {
            writer.write_all(b"{")?;
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            // RFC 8785: Keys are sorted by byte-by-byte comparison of their UTF-8 representations
            entries.sort_by(|(k1, _), (k2, _)| k1.as_bytes().cmp(k2.as_bytes()));
            for (i, (k, v)) in entries.into_iter().enumerate() {
                if i > 0 {
                    writer.write_all(b",")?;
                }
                serde_json::to_writer(&mut *writer, k)?;
                writer.write_all(b":")?;
                canonicalize_to_writer(v, writer)?;
            }
            writer.write_all(b"}")?;
        }
    }
    Ok(())
}

/// Serializes any Serializable data structure to canonical JSON bytes per RFC 8785.
pub fn to_canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, AuditError> {
    let json_val = serde_json::to_value(value)?;
    let mut buf = Vec::new();
    canonicalize_to_writer(&json_val, &mut buf)?;
    Ok(buf)
}

/// Serializes any Serializable data structure to a canonical JSON string per RFC 8785.
pub fn to_canonical_json_string<T: Serialize>(value: &T) -> Result<String, AuditError> {
    let bytes = to_canonical_json_bytes(value)?;
    String::from_utf8(bytes).map_err(|e| AuditError::Canonicalization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_canonical_json_sorting() {
        let val1 = json!({
            "zebra": 1,
            "apple": 2,
            "banana": {
                "d": 4,
                "c": 3
            }
        });

        let val2 = json!({
            "apple": 2,
            "banana": {
                "c": 3,
                "d": 4
            },
            "zebra": 1
        });

        let str1 = to_canonical_json_string(&val1).unwrap();
        let str2 = to_canonical_json_string(&val2).unwrap();

        assert_eq!(str1, str2);
        assert_eq!(str1, r#"{"apple":2,"banana":{"c":3,"d":4},"zebra":1}"#);
    }

    #[test]
    fn test_canonical_json_no_whitespace() {
        let val = json!({
            "items": [1, 2, "three", true, null, {"nested": false}]
        });

        let s = to_canonical_json_string(&val).unwrap();
        assert_eq!(s, r#"{"items":[1,2,"three",true,null,{"nested":false}]}"#);
    }
}
