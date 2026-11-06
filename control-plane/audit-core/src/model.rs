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

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// Constant representation of the Genesis Hash (64 zeros, SHA-256 length).
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Source emitting the audit event.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Source {
    Client,
    Hbbs,
    Hbbr,
    Api,
    Console,
    Builder,
    Other(String),
}

impl Source {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Client => "client",
            Self::Hbbs => "hbbs",
            Self::Hbbr => "hbbr",
            Self::Api => "api",
            Self::Console => "console",
            Self::Builder => "builder",
            Self::Other(s) => s.as_str(),
        }
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Source {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "client" => Self::Client,
            "hbbs" => Self::Hbbs,
            "hbbr" => Self::Hbbr,
            "api" => Self::Api,
            "console" => Self::Console,
            "builder" => Self::Builder,
            other => Self::Other(other.to_string()),
        })
    }
}

impl Serialize for Source {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Source {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from_str(&s).unwrap())
    }
}

/// Category of the audited action.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Category {
    Conn,
    File,
    Alarm,
    Console,
    Auth,
    Build,
    Other(String),
}

impl Category {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Conn => "conn",
            Self::File => "file",
            Self::Alarm => "alarm",
            Self::Console => "console",
            Self::Auth => "auth",
            Self::Build => "build",
            Self::Other(s) => s.as_str(),
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Category {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "conn" => Self::Conn,
            "file" => Self::File,
            "alarm" => Self::Alarm,
            "console" => Self::Console,
            "auth" => Self::Auth,
            "build" => Self::Build,
            other => Self::Other(other.to_string()),
        })
    }
}

impl Serialize for Category {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Category {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from_str(&s).unwrap())
    }
}

/// Outcome of the audited action.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Outcome {
    Success,
    Failure,
    Denied,
    Other(String),
}

impl Outcome {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
            Self::Other(s) => s.as_str(),
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Outcome {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "success" => Self::Success,
            "failure" => Self::Failure,
            "denied" => Self::Denied,
            other => Self::Other(other.to_string()),
        })
    }
}

impl Serialize for Outcome {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Outcome {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from_str(&s).unwrap())
    }
}

fn default_actor_type() -> String {
    "user".to_string()
}

fn default_subject_type() -> String {
    "device".to_string()
}

/// Actor performing the action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Actor {
    pub id: String,
    pub actor_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
}

impl Actor {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            actor_type: default_actor_type(),
            name: None,
            ip: None,
        }
    }

    pub fn with_type(id: impl Into<String>, actor_type: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            actor_type: actor_type.into(),
            name: None,
            ip: None,
        }
    }

    pub fn with_details(
        id: impl Into<String>,
        actor_type: impl Into<String>,
        name: Option<String>,
        ip: Option<String>,
    ) -> Self {
        Self {
            id: id.into(),
            actor_type: actor_type.into(),
            name,
            ip,
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ActorHelper {
    Full {
        id: String,
        #[serde(default = "default_actor_type")]
        actor_type: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        ip: Option<String>,
    },
    Simple(String),
}

impl<'de> Deserialize<'de> for Actor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let helper = ActorHelper::deserialize(deserializer)?;
        match helper {
            ActorHelper::Full {
                id,
                actor_type,
                name,
                ip,
            } => Ok(Actor {
                id,
                actor_type,
                name,
                ip,
            }),
            ActorHelper::Simple(id) => Ok(Actor {
                id,
                actor_type: default_actor_type(),
                name: None,
                ip: None,
            }),
        }
    }
}

/// Subject affected by the action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Subject {
    pub id: String,
    #[serde(rename = "subject_type")]
    pub subject_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl Subject {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            subject_type: default_subject_type(),
            name: None,
        }
    }

    pub fn with_type(id: impl Into<String>, subject_type: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            subject_type: subject_type.into(),
            name: None,
        }
    }

    pub fn with_details(
        id: impl Into<String>,
        subject_type: impl Into<String>,
        name: Option<String>,
    ) -> Self {
        Self {
            id: id.into(),
            subject_type: subject_type.into(),
            name,
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SubjectHelper {
    Full {
        id: String,
        #[serde(default = "default_subject_type", alias = "kind")]
        subject_type: String,
        #[serde(default)]
        name: Option<String>,
    },
    Simple(String),
}

impl<'de> Deserialize<'de> for Subject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let helper = SubjectHelper::deserialize(deserializer)?;
        match helper {
            SubjectHelper::Full {
                id,
                subject_type,
                name,
            } => Ok(Subject {
                id,
                subject_type,
                name,
            }),
            SubjectHelper::Simple(id) => Ok(Subject {
                id,
                subject_type: default_subject_type(),
                name: None,
            }),
        }
    }
}

/// Payload of an audit event subjected to canonical serialization and hashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPayload {
    pub event_id: String,
    pub trace_id: String,
    pub ts: String,
    pub source: Source,
    pub category: Category,
    pub action: String,
    pub actor: Actor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<Subject>,
    pub outcome: Outcome,
    pub details: serde_json::Value,
}

/// Complete stored audit event including sequence, hashes, and timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub sequence: i64,
    pub event_id: String,
    pub trace_id: String,
    pub ts: String,
    pub source: Source,
    pub category: Category,
    pub action: String,
    pub actor: Actor,
    pub subject: Option<Subject>,
    pub outcome: Outcome,
    pub details: serde_json::Value,
    pub prev_hash: String,
    pub hash: String,
    pub created_at: String,
}

impl AuditEvent {
    /// Extracts the canonical `EventPayload` for hash recomputation and verification.
    pub fn payload(&self) -> EventPayload {
        EventPayload {
            event_id: self.event_id.clone(),
            trace_id: self.trace_id.clone(),
            ts: self.ts.clone(),
            source: self.source.clone(),
            category: self.category.clone(),
            action: self.action.clone(),
            actor: self.actor.clone(),
            subject: self.subject.clone(),
            outcome: self.outcome.clone(),
            details: self.details.clone(),
        }
    }
}

/// Input structure to append a new event to the audit store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventInput {
    pub trace_id: String,
    pub source: Source,
    pub category: Category,
    pub action: String,
    pub actor: Actor,
    pub subject: Option<Subject>,
    pub outcome: Outcome,
    pub details: serde_json::Value,
    pub event_id: Option<String>,
    pub ts: Option<String>,
}

impl EventInput {
    pub fn new(
        trace_id: impl Into<String>,
        source: Source,
        category: Category,
        action: impl Into<String>,
        actor: Actor,
        outcome: Outcome,
        details: serde_json::Value,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            source,
            category,
            action: action.into(),
            actor,
            subject: None,
            outcome,
            details,
            event_id: None,
            ts: None,
        }
    }

    pub fn with_subject(mut self, subject: Subject) -> Self {
        self.subject = Some(subject);
        self
    }

    pub fn with_event_id(mut self, event_id: impl Into<String>) -> Self {
        self.event_id = Some(event_id.into());
        self
    }

    pub fn with_ts(mut self, ts: impl Into<String>) -> Self {
        self.ts = Some(ts.into());
        self
    }
}

/// Filter options for querying events from the append-only store.
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    pub trace_id: Option<String>,
    pub category: Option<Category>,
    pub action: Option<String>,
    pub actor_id: Option<String>,
    pub subject_id: Option<String>,
    pub outcome: Option<Outcome>,
    /// Matches `details.severity` case-insensitively (alarm queries).
    pub severity: Option<String>,
    pub from_ts: Option<String>,
    pub to_ts: Option<String>,
    pub from_seq: Option<i64>,
    pub to_seq: Option<i64>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Exclusive lower bound for cursor pagination.
    pub after_sequence: Option<i64>,
}

/// Result of verifying a segment or the entirety of the audit chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationResult {
    pub is_valid: bool,
    pub total_verified: usize,
    pub first_sequence: Option<i64>,
    pub last_sequence: Option<i64>,
    pub error: Option<ChainVerificationError>,
}

impl VerificationResult {
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }

    pub fn corrupted_sequence(&self) -> Option<i64> {
        self.error.as_ref().map(|e| e.sequence)
    }
}

/// Detailed error information if chain verification detects tampering or broken links.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainVerificationError {
    pub sequence: i64,
    pub event_id: String,
    pub reason: String,
    pub expected_hash: Option<String>,
    pub actual_hash: Option<String>,
}
