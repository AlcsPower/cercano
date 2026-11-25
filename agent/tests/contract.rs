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

//! F3.5-03 contract tests: the JSON Schemas in `docs/specs/` accept the valid
//! examples, reject the invalid ones, keep the operation list read-only and
//! keep the configuration code within the `msiexec` budget.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonschema::{Registry, Validator};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const PROFILE_ID: &str = "https://cercano.local/schemas/cercano-profile.schema.json";
const IPC_ID: &str = "https://cercano.local/schemas/agente-ipc.schema.json";
const ORG_ID: &str = "https://cercano.local/schemas/cercano-org.schema.json";
const MAX_CODE_LEN: usize = 4096;

fn specs() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/specs")
}

fn load(path: &Path) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn validator(reference: &str) -> Validator {
    let registry = Registry::new()
        .add(
            PROFILE_ID,
            load(&specs().join("cercano-profile.schema.json")),
        )
        .unwrap()
        .add(IPC_ID, load(&specs().join("agente-ipc.schema.json")))
        .unwrap()
        .add(ORG_ID, load(&specs().join("cercano-org.schema.json")))
        .unwrap()
        .prepare()
        .unwrap();
    jsonschema::options()
        .with_registry(&registry)
        .build(&json!({ "$ref": reference }))
        .unwrap_or_else(|e| panic!("schema {reference} does not compile: {e}"))
}

fn errors(v: &Validator, instance: &Value) -> Vec<String> {
    v.iter_errors(instance).map(|e| e.to_string()).collect()
}

fn examples(prefix: &str) -> Vec<(String, Value)> {
    let dir = specs().join("examples/agente-ipc");
    let mut found: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            let name = p.file_name().unwrap().to_string_lossy();
            name.starts_with(prefix) && name.ends_with(".json")
        })
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                load(&p),
            )
        })
        .collect();
    found.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(!found.is_empty(), "no examples with prefix {prefix}");
    found
}

#[test]
fn ipc_valid_exchanges_validate() {
    let message = validator(IPC_ID);
    let exchanges = load(&specs().join("examples/agente-ipc/ipc-validos.json"));
    for (i, ex) in exchanges.as_array().unwrap().iter().enumerate() {
        for part in ["request", "response", "event"] {
            if let Some(m) = ex.get(part) {
                assert_eq!(errors(&message, m), Vec::<String>::new(), "#{i} {part}");
            }
        }
        // Successful results also validate against definitions/results/<op>.
        if let (Some(op), Some(result)) = (ex.get("op"), ex.pointer("/response/result")) {
            let op = op.as_str().unwrap();
            let v = validator(&format!("{IPC_ID}#/definitions/results/{op}"));
            assert_eq!(
                errors(&v, result),
                Vec::<String>::new(),
                "#{i} result of {op}"
            );
        }
    }
}

#[test]
fn ipc_invalid_messages_are_rejected() {
    let message = validator(IPC_ID);
    let cases = load(&specs().join("examples/agente-ipc/ipc-invalidos.json"));
    for case in cases.as_array().unwrap() {
        assert!(
            !message.is_valid(&case["mensaje"]),
            "should be rejected: {}",
            case["motivo"]
        );
    }
}

#[test]
fn every_op_has_a_result_schema() {
    let schema = load(&specs().join("agente-ipc.schema.json"));
    let results = schema["definitions"]["results"].as_object().unwrap();
    for op in schema["definitions"]["op"]["enum"].as_array().unwrap() {
        assert!(
            results.contains_key(op.as_str().unwrap()),
            "{op} has no result schema"
        );
    }
}

#[test]
fn no_config_write_ops() {
    let schema = load(&specs().join("agente-ipc.schema.json"));
    let ops: Vec<&str> = schema["definitions"]["op"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    // The closed list approved in docs/specs/agente-ipc.md §6. Changing it needs Security sign-off.
    assert_eq!(
        ops,
        [
            "hello",
            "get_config",
            "get_branding",
            "get_role",
            "get_policy",
            "chat.list_conversations",
            "chat.get_messages",
            "chat.send_message",
            "chat.mark_read",
            "chat.subscribe",
            "chat.get_attachment",
            "audit.submit",
            "status",
        ]
    );
    for op in &ops {
        let lower = op.to_ascii_lowercase();
        for word in [
            "set", "write", "update", "enroll", "pin", "key", "delete", "revoke",
        ] {
            assert!(
                !lower.contains(word),
                "{op} looks like a write operation ({word})"
            );
        }
        if lower.contains("config") || lower.contains("policy") {
            assert!(lower.starts_with("get_"), "{op} must be read-only");
        }
    }
}

#[test]
fn org_examples_validate_or_are_rejected() {
    let org = validator(ORG_ID);
    for (name, config) in examples("org-valido-") {
        assert_eq!(errors(&org, &config), Vec::<String>::new(), "{name}");
    }
    for (name, config) in examples("org-invalido-") {
        assert!(!org.is_valid(&config), "{name} should be rejected");
    }
}

fn encode(config: &Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(config).unwrap())
}

#[test]
fn config_code_roundtrips_and_fits_msiexec() {
    let org = validator(ORG_ID);
    let typical = load(&specs().join("examples/agente-ipc/org-valido-soporte.json"));
    let code = encode(&typical);
    println!("typical configuration code: {} characters", code.len());
    assert!(code.len() <= MAX_CODE_LEN);

    // Largest realistic configuration: every free-text field the generator
    // offers at its schema limit (multi-byte name), growing about_text until
    // the code reaches the 4096-character budget.
    let mut big = typical.clone();
    big["organization_name"] = json!("Ñ".repeat(128));
    big["enroll_token"] = json!("A".repeat(128));
    big["signed_profile"]["key_id"] = json!("k".repeat(64));
    let profile = &mut big["signed_profile"]["profile"];
    profile["identity"]["app_name"] = json!("Á".repeat(64));
    profile["server"]["rendezvous_server"] = json!(format!("{}.example:21116", "r".repeat(60)));
    profile["server"]["relay_server"] = json!(format!("{}.example:21117", "h".repeat(60)));
    let mut about = 0;
    while about < 1024 {
        big["signed_profile"]["profile"]["identity"]["about_text"] = json!("a".repeat(about + 1));
        if encode(&big).len() > MAX_CODE_LEN {
            break;
        }
        about += 1;
    }
    big["signed_profile"]["profile"]["identity"]["about_text"] = json!("a".repeat(about));
    let code = encode(&big);
    println!("maximal configuration code: {} characters", code.len());
    assert!(code.len() <= MAX_CODE_LEN);
    assert!(code
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));

    let decoded: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&code).unwrap()).unwrap();
    assert_eq!(decoded, big);
    assert_eq!(errors(&org, &decoded), Vec::<String>::new());

    // A code at the limit fits in a cmd.exe line (8191) and in CreateProcess (32767).
    let at_limit = "A".repeat(MAX_CODE_LEN);
    let line = format!(
        r#"msiexec /i "C:\Despliegue\cercano.msi" /qn /l*v "C:\Despliegue\cercano-install.log" CERCANO_CONFIG={at_limit}"#
    );
    assert!(
        line.len() < 8191,
        "msiexec line is {} characters",
        line.len()
    );
}
