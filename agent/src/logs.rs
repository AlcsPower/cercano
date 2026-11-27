// Copyright (C) 2026 Cercano Contributors
//
// This file is part of Cercano.
//
// Cercano is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Rotated agent log with secret redaction (F3.5-04).
//!
//! Every line goes through [`redact`] before it touches disk, and diagnostics
//! redact again on export, so a secret has to slip past both to leak.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub const LOG_FILE: &str = "agent.log";
// Writing happens in the Windows service; other platforms only read (and test).
#[cfg_attr(not(windows), allow(dead_code))]
const MAX_BYTES: u64 = 1024 * 1024;
#[cfg_attr(not(windows), allow(dead_code))]
const KEEP: usize = 5;
const REDACTED: &str = "[REDACTED]";

/// Words that, followed by `:` or `=`, introduce a secret value.
const SECRET_KEYS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "private",
    "signature",
    "credential",
    "authorization",
    "bearer",
    "api_key",
    "apikey",
];

pub fn log_dir(store: &Path) -> PathBuf {
    store.join("logs")
}

/// Appends one redacted line, rotating `agent.log` → `agent.log.1` … `agent.log.5`.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn write(dir: &Path, level: &str, msg: &str) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let path = dir.join(LOG_FILE);
    if fs::metadata(&path)
        .map(|m| m.len() >= MAX_BYTES)
        .unwrap_or(false)
    {
        rotate(dir)?;
    }
    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let line = redact(&msg.replace(['\r', '\n'], " "));
    let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(f, "{ts} {level} {line}")
}

#[cfg_attr(not(windows), allow(dead_code))]
fn rotate(dir: &Path) -> io::Result<()> {
    let name = |i: usize| dir.join(format!("{LOG_FILE}.{i}"));
    let _ = fs::remove_file(name(KEEP));
    for i in (1..KEEP).rev() {
        if name(i).exists() {
            fs::rename(name(i), name(i + 1))?;
        }
    }
    fs::rename(dir.join(LOG_FILE), name(1))
}

/// Last `n` lines across `agent.log.1` and `agent.log`.
pub fn tail(dir: &Path, n: usize) -> io::Result<Vec<String>> {
    let current = fs::read_to_string(dir.join(LOG_FILE))?;
    let previous = fs::read_to_string(dir.join(format!("{LOG_FILE}.1"))).unwrap_or_default();
    let lines: Vec<String> = previous
        .lines()
        .chain(current.lines())
        .map(str::to_owned)
        .collect();
    Ok(lines[lines.len().saturating_sub(n)..].to_vec())
}

/// Removes secret-looking values: `key=value` / `"key": "value"` pairs whose key
/// contains a word of [`SECRET_KEYS`], and long base64/hex runs (keys, tokens,
/// signatures) wherever they appear.
pub fn redact(input: &str) -> String {
    redact_long_runs(&redact_pairs(input))
}

fn is_value_end(b: u8) -> bool {
    b.is_ascii_whitespace() || matches!(b, b'"' | b'\'' | b',' | b'}' | b']' | b'&' | b';')
}

fn redact_pairs(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        // Compare bytes: `i` advances byte by byte and may fall inside a multi-byte char.
        let Some(key) = SECRET_KEYS
            .iter()
            .find(|k| lower.as_bytes()[i..].starts_with(k.as_bytes()))
        else {
            i += 1;
            continue;
        };
        // Skip the rest of the key word (e.g. `enroll_token`), then separators.
        let mut j = i + key.len();
        while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
            j += 1;
        }
        let sep_start = j;
        while j < bytes.len() && matches!(bytes[j], b'"' | b'\'' | b' ' | b':' | b'=') {
            j += 1;
        }
        let has_sep = bytes[sep_start..j].iter().any(|b| matches!(b, b':' | b'='));
        // `Bearer <value>` has no separator.
        let bearer = *key == "bearer" && j > sep_start;
        if !(has_sep || bearer) {
            i = j.max(i + 1);
            continue;
        }
        let value_end = |mut k: usize| {
            while k < bytes.len() && !is_value_end(bytes[k]) {
                k += 1;
            }
            k
        };
        let mut k = value_end(j);
        // `Authorization: Bearer <value>`: the secret is the word after the scheme.
        if &lower.as_bytes()[j..k] == b"bearer" {
            while k < bytes.len() && bytes[k] == b' ' {
                k += 1;
            }
            k = value_end(k);
        }
        if k > j {
            out.push_str(&input[copied..j]);
            out.push_str(REDACTED);
            copied = k;
        }
        i = k.max(i + 1);
    }
    out.push_str(&input[copied..]);
    out
}

fn is_run_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

/// A run of 32+ base64 characters mixing upper, lower and digits (random keys and
/// tokens), or 40+ hex characters. Paths and UUIDs do not match.
fn looks_secret(run: &str) -> bool {
    let b = run.as_bytes();
    let mixed = b.iter().any(u8::is_ascii_uppercase)
        && b.iter().any(u8::is_ascii_lowercase)
        && b.iter().any(u8::is_ascii_digit);
    (b.len() >= 32 && mixed) || (b.len() >= 40 && b.iter().all(u8::is_ascii_hexdigit))
}

fn redact_long_runs(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if !is_run_byte(bytes[i]) {
            let start = i;
            while i < bytes.len() && !is_run_byte(bytes[i]) {
                i += 1;
            }
            out.push_str(&input[start..i]);
            continue;
        }
        let start = i;
        while i < bytes.len() && is_run_byte(bytes[i]) {
            i += 1;
        }
        let run = &input[start..i];
        out.push_str(if looks_secret(run) { REDACTED } else { run });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "Q2VyY2Fub0VqZW1wbG9DbGF2ZVB1YmxpY2EwMDAwMDE=";

    #[test]
    fn redacts_pairs_and_long_runs() {
        let cases = [
            ("enroll_token=abc123", "enroll_token=[REDACTED]"),
            (
                r#"{"enroll_token": "short"}"#,
                r#"{"enroll_token": "[REDACTED]"}"#,
            ),
            ("Authorization: Bearer xyz", "Authorization: [REDACTED]"),
            ("header Bearer xyz.abc", "header Bearer [REDACTED]"),
            ("password = hunter2;", "password = [REDACTED];"),
            (
                "contraseña password=ñandú1",
                "contraseña password=[REDACTED]",
            ),
            ("tóken token=ñ€😀x fin", "tóken token=[REDACTED] fin"),
        ];
        for (input, expected) in cases {
            assert_eq!(redact(input), expected, "input: {input}");
        }
        let out = redact(&format!("pinned key {KEY} ok"));
        assert_eq!(out, "pinned key [REDACTED] ok");
        let hex = "a".repeat(20) + &"0".repeat(44);
        assert_eq!(redact(&format!("sha {hex}")), "sha [REDACTED]");
    }

    #[test]
    fn keeps_harmless_text() {
        for s in [
            "service started, store C:\\ProgramData\\Cercano\\agent",
            "/var/lib/cercano-agent/logs/agent.log rotated",
            "profile 0192e300-1111-7111-8111-000000000001 loaded",
            "tokens are never logged",
            "estado: sin vincular",
            "servicio iniciado (versión 0.1.0), almacén C:\\Users\\José",
            "año ñ€😀 Ünïcödé sin secretos",
        ] {
            assert_eq!(redact(s), s);
        }
    }

    #[test]
    fn rotates_and_tails() {
        let dir = tempfile::tempdir().unwrap();
        let big = "x".repeat(1000);
        for i in 0..1100 {
            write(dir.path(), "INFO", &format!("{i} {big}")).unwrap();
        }
        assert!(dir.path().join("agent.log.1").exists());
        assert!(fs::metadata(dir.path().join(LOG_FILE)).unwrap().len() < MAX_BYTES);
        let last = tail(dir.path(), 3).unwrap();
        assert_eq!(last.len(), 3);
        assert!(last[2].contains(" INFO 1099 "));
    }

    #[test]
    fn written_lines_are_redacted_and_single_line() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "WARN", &format!("token={KEY}\nforged line")).unwrap();
        let text = fs::read_to_string(dir.path().join(LOG_FILE)).unwrap();
        assert!(!text.contains(KEY));
        assert_eq!(text.lines().count(), 1);
    }
}
