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

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use serde_json::json;

use audit_core::{Actor, AuditError, AuditEvent, Category, EventInput, Outcome, Source, Subject};

use crate::config::Config;

/// Parses an IP address from a string, handling optional port or IPv6 brackets.
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(socket) = s.parse::<std::net::SocketAddr>() {
        return Some(socket.ip());
    }
    if let Some(stripped) = s.strip_prefix('[').and_then(|r| r.split("]:").next()) {
        if let Ok(ip) = stripped.parse::<IpAddr>() {
            return Some(ip);
        }
    }
    if let Some((host, _port)) = s.split_once(':') {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Some(ip);
        }
    }
    None
}

/// Checks whether an `IpAddr` matches a CIDR range string (e.g. `192.168.1.0/24`, `10.0.0.0/8`, `::1/128`, or exact IP).
pub fn ip_matches_cidr(ip: &IpAddr, cidr: &str) -> bool {
    let cidr = cidr.trim();
    if let Ok(exact_ip) = cidr.parse::<IpAddr>() {
        return ip == &exact_ip;
    }

    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }

    let net_ip = match parts[0].trim().parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    let prefix: u32 = match parts[1].trim().parse() {
        Ok(p) => p,
        Err(_) => return false,
    };

    match (ip, net_ip) {
        (IpAddr::V4(addr), IpAddr::V4(net)) => {
            if prefix > 32 {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let mask = !0u32 << (32 - prefix);
            (u32::from(*addr) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(addr), IpAddr::V6(net)) => {
            if prefix > 128 {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let mask = !0u128 << (128 - prefix);
            (u128::from(*addr) & mask) == (u128::from(net) & mask)
        }
        _ => false,
    }
}

/// Validates an IP against a whitelist of CIDR / IP patterns.
/// If `whitelist` is empty, all IPs are considered allowed (whitelist is disabled).
pub fn is_ip_in_whitelist(ip_str: &str, whitelist: &[String]) -> bool {
    if whitelist.is_empty() {
        return true;
    }
    let ip = match parse_ip(ip_str) {
        Some(ip) => ip,
        None => return false,
    };
    whitelist.iter().any(|cidr| ip_matches_cidr(&ip, cidr))
}

/// Configuration settings for the alarm rules engine.
#[derive(Debug, Clone)]
pub struct AlarmConfig {
    /// Maximum failed logins allowed before triggering `alarm.brute_force` (default: 5).
    pub brute_force_threshold: usize,
    /// Sliding window duration in seconds for failed logins (default: 900 seconds / 15 minutes).
    pub brute_force_window_secs: i64,
    /// Maximum connection/login attempts from a single IP before triggering `alarm.ip_burst` (default: 30).
    pub ip_burst_threshold: usize,
    /// Sliding window duration in seconds for IP bursts (default: 60 seconds / 1 minute).
    pub ip_burst_window_secs: i64,
    /// Configured CIDR whitelist ranges. If empty, whitelist enforcement is disabled.
    pub ip_whitelist: Vec<String>,
}

impl Default for AlarmConfig {
    fn default() -> Self {
        Self {
            brute_force_threshold: 5,
            brute_force_window_secs: 900,
            ip_burst_threshold: 30,
            ip_burst_window_secs: 60,
            ip_whitelist: Vec::new(),
        }
    }
}

/// Alarm evaluation engine managing sliding window rate tracking and rule triggers.
pub struct AlarmEngine {
    config: AlarmConfig,
    audit: Arc<audit_core::AuditStore>,
    failed_logins: Mutex<HashMap<String, Vec<DateTime<Utc>>>>,
    ip_attempts: Mutex<HashMap<String, Vec<DateTime<Utc>>>>,
}

impl AlarmEngine {
    /// Creates a new `AlarmEngine` using settings from `Config` and the shared `AuditStore`.
    pub fn new(config: Config, audit: Arc<audit_core::AuditStore>) -> Self {
        let alarm_config = AlarmConfig {
            ip_whitelist: config.ip_whitelist,
            ..Default::default()
        };
        Self::with_config(alarm_config, audit)
    }

    /// Creates a new `AlarmEngine` with custom `AlarmConfig` and `AuditStore`.
    pub fn with_config(config: AlarmConfig, audit: Arc<audit_core::AuditStore>) -> Self {
        Self {
            config,
            audit,
            failed_logins: Mutex::new(HashMap::new()),
            ip_attempts: Mutex::new(HashMap::new()),
        }
    }

    /// Returns a reference to the underlying `AuditStore`.
    pub fn audit_store(&self) -> &Arc<audit_core::AuditStore> {
        &self.audit
    }

    /// Returns a reference to the active `AlarmConfig`.
    pub fn config(&self) -> &AlarmConfig {
        &self.config
    }

    /// Checks if a client IP is authorized according to the configured whitelist.
    pub fn is_ip_whitelisted(&self, ip_str: &str) -> bool {
        is_ip_in_whitelist(ip_str, &self.config.ip_whitelist)
    }

    /// Evaluates IP whitelist for access attempts.
    ///
    /// If an IP whitelist is configured and the provided IP address is outside all
    /// configured CIDR ranges, automatically records an `alarm.ip_whitelist_violation`
    /// event directly into `AuditStore` and returns `Some(event)`.
    /// If access is authorized or no whitelist is configured, returns `None`.
    pub async fn check_ip_whitelist(
        &self,
        ip_str: &str,
        trace_id: Option<&str>,
        actor_id: Option<&str>,
    ) -> Result<Option<AuditEvent>, AuditError> {
        if self.config.ip_whitelist.is_empty() {
            return Ok(None);
        }

        if self.is_ip_whitelisted(ip_str) {
            return Ok(None);
        }

        // Whitelist violation detected
        let trace = trace_id
            .map(String::from)
            .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
        let actor = Actor::with_details(
            actor_id.unwrap_or("sys_alarm_engine"),
            "system",
            Some("AlarmEngine".to_string()),
            Some(ip_str.to_string()),
        );
        let subject = Subject::with_details(ip_str, "ip_address", None);

        let details = json!({
            "alarm_name": "alarm.ip_whitelist_violation",
            "severity": "high",
            "reason": "Access attempt from IP outside configured whitelist",
            "ip": ip_str,
            "configured_whitelist": self.config.ip_whitelist
        });

        let input = EventInput::new(
            trace,
            Source::Api,
            Category::Alarm,
            "alarm.ip_whitelist_violation",
            actor,
            Outcome::Denied,
            details,
        )
        .with_subject(subject);

        let event = self.audit.append(input).await?;
        Ok(Some(event))
    }

    /// Records an access, connection, or login attempt from a client IP address.
    ///
    /// If more than 30 attempts (> `ip_burst_threshold`) occur from the same IP address
    /// within a 1-minute window, automatically records an `alarm.ip_burst` event
    /// directly to `AuditStore` and returns `Some(event)`.
    pub async fn record_ip_attempt(
        &self,
        ip_str: &str,
        trace_id: Option<&str>,
        actor_id: Option<&str>,
    ) -> Result<Option<AuditEvent>, AuditError> {
        let now = Utc::now();
        let cutoff = now - Duration::seconds(self.config.ip_burst_window_secs);

        let count = {
            let mut lock = self.ip_attempts.lock().unwrap();
            let entries = lock.entry(ip_str.to_string()).or_default();
            entries.retain(|t| *t > cutoff);
            entries.push(now);
            entries.len()
        };

        if count > self.config.ip_burst_threshold {
            let trace = trace_id
                .map(String::from)
                .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
            let actor = Actor::with_details(
                actor_id.unwrap_or("sys_alarm_engine"),
                "system",
                Some("AlarmEngine".to_string()),
                Some(ip_str.to_string()),
            );
            let subject = Subject::with_details(ip_str, "ip_address", None);

            let details = json!({
                "alarm_name": "alarm.ip_burst",
                "severity": "critical",
                "reason": "Exceeded 30 connection/login attempts from single IP address in 1 minute",
                "attempts": count,
                "window_secs": self.config.ip_burst_window_secs,
                "ip": ip_str
            });

            let input = EventInput::new(
                trace,
                Source::Api,
                Category::Alarm,
                "alarm.ip_burst",
                actor,
                Outcome::Denied,
                details,
            )
            .with_subject(subject);

            let event = self.audit.append(input).await?;
            return Ok(Some(event));
        }

        Ok(None)
    }

    /// Records a failed authentication/login attempt for a subject (user ID or username).
    ///
    /// If more than 5 failed logins (> `brute_force_threshold`) occur within a 15-minute window
    /// for that subject, automatically records an `alarm.brute_force` event directly
    /// to `AuditStore` and returns `Some(event)`.
    pub async fn record_login_failure(
        &self,
        user_or_subject: &str,
        ip_str: Option<&str>,
        trace_id: Option<&str>,
    ) -> Result<Option<AuditEvent>, AuditError> {
        let now = Utc::now();
        let cutoff = now - Duration::seconds(self.config.brute_force_window_secs);

        let count = {
            let mut lock = self.failed_logins.lock().unwrap();
            let entries = lock.entry(user_or_subject.to_string()).or_default();
            entries.retain(|t| *t > cutoff);
            entries.push(now);
            entries.len()
        };

        if count > self.config.brute_force_threshold {
            let trace = trace_id
                .map(String::from)
                .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
            let actor = Actor::with_details(
                "sys_alarm_engine",
                "system",
                Some("AlarmEngine".to_string()),
                ip_str.map(String::from),
            );
            let subject = Subject::with_details(user_or_subject, "user", None);

            let details = json!({
                "alarm_name": "alarm.brute_force",
                "severity": "high",
                "reason": "Exceeded 5 failed login attempts within 15 minutes for user/subject",
                "failed_attempts": count,
                "window_secs": self.config.brute_force_window_secs,
                "username": user_or_subject,
                "ip": ip_str
            });

            let input = EventInput::new(
                trace,
                Source::Api,
                Category::Alarm,
                "alarm.brute_force",
                actor,
                Outcome::Denied,
                details,
            )
            .with_subject(subject);

            let event = self.audit.append(input).await?;
            return Ok(Some(event));
        }

        Ok(None)
    }

    /// Records an unauthorized device group or out-of-scope session attempt (`alarm.scope_violation`).
    pub async fn record_scope_violation(
        &self,
        actor_id: &str,
        actor_ip: Option<&str>,
        target_device_or_group: &str,
        reason: &str,
        trace_id: Option<&str>,
    ) -> Result<AuditEvent, AuditError> {
        let trace = trace_id
            .map(String::from)
            .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
        let actor = Actor::with_details(actor_id, "user", None, actor_ip.map(String::from));
        let subject = Subject::with_details(target_device_or_group, "device_group", None);

        let details = json!({
            "alarm_name": "alarm.scope_violation",
            "severity": "high",
            "reason": reason,
            "actor_id": actor_id,
            "target": target_device_or_group
        });

        let input = EventInput::new(
            trace,
            Source::Api,
            Category::Alarm,
            "alarm.scope_violation",
            actor,
            Outcome::Denied,
            details,
        )
        .with_subject(subject);

        self.audit.append(input).await
    }

    /// Evaluates if a session target is within an actor's authorized scopes.
    /// If not in `allowed_scopes`, triggers an `alarm.scope_violation`.
    pub async fn check_session_scope(
        &self,
        actor_id: &str,
        actor_ip: Option<&str>,
        target_device_or_group: &str,
        allowed_scopes: &[String],
        trace_id: Option<&str>,
    ) -> Result<Option<AuditEvent>, AuditError> {
        if allowed_scopes
            .iter()
            .any(|scope| scope == target_device_or_group)
        {
            return Ok(None);
        }

        let reason = format!(
            "Session attempt to unauthorized device or group '{}'",
            target_device_or_group
        );
        let event = self
            .record_scope_violation(
                actor_id,
                actor_ip,
                target_device_or_group,
                &reason,
                trace_id,
            )
            .await?;
        Ok(Some(event))
    }

    /// Evaluates an arbitrary ingested audit event against security alarm policies.
    pub async fn evaluate_event(&self, event: &AuditEvent) -> Result<Vec<AuditEvent>, AuditError> {
        let mut triggered = Vec::new();

        // 1. IP whitelist check
        if let Some(ref ip) = event.actor.ip {
            if let Some(alarm) = self
                .check_ip_whitelist(ip, Some(&event.trace_id), Some(&event.actor.id))
                .await?
            {
                triggered.push(alarm);
            }

            // 2. IP burst tracking
            if let Some(alarm) = self
                .record_ip_attempt(ip, Some(&event.trace_id), Some(&event.actor.id))
                .await?
            {
                triggered.push(alarm);
            }
        }

        // 3. Failed login / auth brute force check
        if event.category == Category::Auth && event.outcome == Outcome::Failure {
            let target_subject = event
                .subject
                .as_ref()
                .map(|s| s.id.as_str())
                .unwrap_or(event.actor.id.as_str());

            if let Some(alarm) = self
                .record_login_failure(
                    target_subject,
                    event.actor.ip.as_deref(),
                    Some(&event.trace_id),
                )
                .await?
            {
                triggered.push(alarm);
            }
        }

        Ok(triggered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip_variants() {
        assert_eq!(
            parse_ip("192.168.1.1").unwrap(),
            "192.168.1.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            parse_ip("192.168.1.1:8080").unwrap(),
            "192.168.1.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(parse_ip("::1").unwrap(), "::1".parse::<IpAddr>().unwrap());
        assert_eq!(
            parse_ip("[::1]:8080").unwrap(),
            "::1".parse::<IpAddr>().unwrap()
        );
        assert!(parse_ip("not_an_ip").is_none());
    }

    #[test]
    fn test_ip_matches_cidr_v4() {
        let ip = "192.168.1.50".parse::<IpAddr>().unwrap();
        assert!(ip_matches_cidr(&ip, "192.168.1.0/24"));
        assert!(ip_matches_cidr(&ip, "192.168.0.0/16"));
        assert!(ip_matches_cidr(&ip, "192.168.1.50/32"));
        assert!(ip_matches_cidr(&ip, "192.168.1.50"));
        assert!(!ip_matches_cidr(&ip, "192.168.2.0/24"));
        assert!(!ip_matches_cidr(&ip, "10.0.0.0/8"));
    }

    #[test]
    fn test_ip_matches_cidr_v6() {
        let ip = "fd00::1".parse::<IpAddr>().unwrap();
        assert!(ip_matches_cidr(&ip, "fd00::/8"));
        assert!(ip_matches_cidr(&ip, "fd00::1/128"));
        assert!(!ip_matches_cidr(&ip, "2001:db8::/32"));
    }

    #[test]
    fn test_whitelist_checking() {
        let whitelist = vec![
            "10.0.0.0/8".to_string(),
            "192.168.1.0/24".to_string(),
            "127.0.0.1".to_string(),
        ];

        // Inside whitelist
        assert!(is_ip_in_whitelist("10.5.1.20", &whitelist));
        assert!(is_ip_in_whitelist("192.168.1.100", &whitelist));
        assert!(is_ip_in_whitelist("127.0.0.1", &whitelist));

        // Outside whitelist
        assert!(!is_ip_in_whitelist("172.16.0.1", &whitelist));
        assert!(!is_ip_in_whitelist("8.8.8.8", &whitelist));

        // Empty whitelist means no restriction
        assert!(is_ip_in_whitelist("8.8.8.8", &[]));
    }
}
