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
    /// Maximum elevation requests allowed for a single technician before triggering `alarm.elev_frequency` (default: 3).
    pub elev_frequency_threshold: usize,
    /// Sliding window duration in seconds for technician elevation requests (default: 600 seconds / 10 minutes).
    pub elev_frequency_window_secs: i64,
    /// Maximum consecutive rejected elevation requests before triggering `alarm.elev_rejections` (default: 2).
    pub elev_rejections_threshold: usize,
    /// Whether after-hours elevation detection is enabled (default: true).
    pub elev_after_hours_enabled: bool,
    /// Start hour for standard business hours (UTC, 0..23, inclusive, default: 7).
    pub elev_business_hours_start: u32,
    /// End hour for standard business hours (UTC, 0..23, exclusive, default: 19).
    pub elev_business_hours_end: u32,
    /// Whether after-hours alarm triggers on weekends (Saturday & Sunday, default: true).
    pub elev_weekends_are_after_hours: bool,
}

impl Default for AlarmConfig {
    fn default() -> Self {
        Self {
            brute_force_threshold: 5,
            brute_force_window_secs: 900,
            ip_burst_threshold: 30,
            ip_burst_window_secs: 60,
            ip_whitelist: Vec::new(),
            elev_frequency_threshold: 3,
            elev_frequency_window_secs: 600,
            elev_rejections_threshold: 2,
            elev_after_hours_enabled: true,
            elev_business_hours_start: 7,
            elev_business_hours_end: 19,
            elev_weekends_are_after_hours: true,
        }
    }
}

/// Alarm evaluation engine managing sliding window rate tracking and rule triggers.
pub struct AlarmEngine {
    config: AlarmConfig,
    audit: Arc<audit_core::AuditStore>,
    failed_logins: Mutex<HashMap<String, Vec<DateTime<Utc>>>>,
    ip_attempts: Mutex<HashMap<String, Vec<DateTime<Utc>>>>,
    technician_elevations: Mutex<HashMap<String, Vec<DateTime<Utc>>>>,
    consecutive_rejections: Mutex<HashMap<String, usize>>,
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
            technician_elevations: Mutex::new(HashMap::new()),
            consecutive_rejections: Mutex::new(HashMap::new()),
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
            // Bound memory: drop addresses that have been silent for a full window.
            if lock.len() > 1024 {
                lock.retain(|_, entries| {
                    entries.retain(|t| *t > cutoff);
                    !entries.is_empty()
                });
            }
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
            // Bound memory: drop subjects that have been silent for a full window.
            if lock.len() > 1024 {
                lock.retain(|_, entries| {
                    entries.retain(|t| *t > cutoff);
                    !entries.is_empty()
                });
            }
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

    /// Records a role enforcement violation alarm (`alarm.role_violation`).
    ///
    /// Triggered when an installer or device attempts an operation unauthorized for its role
    /// (e.g. `soporte` attempting remote connection initiation or privilege elevation),
    /// or when a client attempts role spoofing / tampering.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_role_violation(
        &self,
        actor_id: &str,
        actor_ip: Option<&str>,
        installer_id: Option<&str>,
        actual_role: &str,
        attempted_role_or_op: &str,
        reason: &str,
        trace_id: Option<&str>,
    ) -> Result<AuditEvent, AuditError> {
        let trace = trace_id
            .map(String::from)
            .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
        let actor = Actor::with_details(actor_id, "device", None, actor_ip.map(String::from));
        let subject = Subject::with_details(
            installer_id.unwrap_or(actor_id),
            "installer",
            Some(actual_role.to_string()),
        );

        let details = json!({
            "alarm_name": "alarm.role_violation",
            "severity": "critical",
            "reason": reason,
            "installer_id": installer_id,
            "actual_role": actual_role,
            "attempted_role_or_operation": attempted_role_or_op,
            "ip": actor_ip,
        });

        let input = EventInput::new(
            trace,
            Source::Api,
            Category::Alarm,
            "alarm.role_violation",
            actor,
            Outcome::Denied,
            details,
        )
        .with_subject(subject);

        self.audit.append(input).await
    }

    /// Checks whether a given timestamp is outside configured business hours (or on a weekend).
    pub fn is_after_hours(&self, dt: &DateTime<Utc>) -> bool {
        if !self.config.elev_after_hours_enabled {
            return false;
        }

        use chrono::{Datelike, Timelike, Weekday};
        if self.config.elev_weekends_are_after_hours {
            let weekday = dt.weekday();
            if weekday == Weekday::Sat || weekday == Weekday::Sun {
                return true;
            }
        }

        let hour = dt.hour();
        if self.config.elev_business_hours_start < self.config.elev_business_hours_end {
            // Normal daytime window, e.g. 7:00 to 19:00
            hour < self.config.elev_business_hours_start
                || hour >= self.config.elev_business_hours_end
        } else {
            // Nighttime window crossing midnight, e.g. 22:00 to 6:00
            hour < self.config.elev_business_hours_start
                && hour >= self.config.elev_business_hours_end
        }
    }

    /// Records an elevation request or execution attempt for a technician.
    ///
    /// If more than 3 elevations (> `elev_frequency_threshold`) occur from the same technician
    /// within a 10-minute window (`elev_frequency_window_secs`), automatically records an
    /// `alarm.elev_frequency` event directly into `AuditStore` and returns `Some(event)`.
    pub async fn record_elevation_attempt(
        &self,
        technician_id: &str,
        target_device: Option<&str>,
        actor_ip: Option<&str>,
        trace_id: Option<&str>,
        event_time: Option<DateTime<Utc>>,
    ) -> Result<Option<AuditEvent>, AuditError> {
        let now = event_time.unwrap_or_else(Utc::now);
        let cutoff = now - Duration::seconds(self.config.elev_frequency_window_secs);

        let count = {
            let mut lock = self.technician_elevations.lock().unwrap();
            if lock.len() > 1024 {
                lock.retain(|_, entries| {
                    entries.retain(|t| *t > cutoff);
                    !entries.is_empty()
                });
            }
            let entries = lock.entry(technician_id.to_string()).or_default();
            entries.retain(|t| *t > cutoff);
            entries.push(now);
            entries.len()
        };

        if count > self.config.elev_frequency_threshold {
            let trace = trace_id
                .map(String::from)
                .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
            let actor = Actor::with_details(
                technician_id,
                "user",
                Some(technician_id.to_string()),
                actor_ip.map(String::from),
            );
            let subject = target_device.map(|dev| Subject::with_details(dev, "device", None));

            let details = json!({
                "alarm_name": "alarm.elev_frequency",
                "severity": "high",
                "reason": format!(
                    "Technician '{}' exceeded {} elevation attempts within {} minutes",
                    technician_id,
                    self.config.elev_frequency_threshold,
                    self.config.elev_frequency_window_secs / 60
                ),
                "attempts": count,
                "threshold": self.config.elev_frequency_threshold,
                "window_secs": self.config.elev_frequency_window_secs,
                "technician_id": technician_id,
                "target_device": target_device,
            });

            let mut input = EventInput::new(
                trace,
                Source::Api,
                Category::Alarm,
                "alarm.elev_frequency",
                actor,
                Outcome::Denied,
                details,
            );
            if let Some(subj) = subject {
                input = input.with_subject(subj);
            }

            let event = self.audit.append(input).await?;
            return Ok(Some(event));
        }

        Ok(None)
    }

    /// Records a rejected elevation request.
    ///
    /// If more than 2 consecutive rejections (> `elev_rejections_threshold`) occur for
    /// the technician/device, automatically records an `alarm.elev_rejections` event
    /// directly to `AuditStore` and returns `Some(event)`.
    pub async fn record_elevation_rejection(
        &self,
        technician_id: &str,
        target_device: Option<&str>,
        actor_ip: Option<&str>,
        trace_id: Option<&str>,
        rejection_reason: Option<&str>,
    ) -> Result<Option<AuditEvent>, AuditError> {
        let key = if let Some(dev) = target_device {
            format!("{}:{}", technician_id, dev)
        } else {
            technician_id.to_string()
        };

        let count = {
            let mut lock = self.consecutive_rejections.lock().unwrap();
            let entry = lock.entry(key).or_insert(0);
            *entry += 1;
            *entry
        };

        if count > self.config.elev_rejections_threshold {
            let trace = trace_id
                .map(String::from)
                .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
            let actor = Actor::with_details(
                technician_id,
                "user",
                Some(technician_id.to_string()),
                actor_ip.map(String::from),
            );
            let subject = target_device.map(|dev| Subject::with_details(dev, "device", None));

            let details = json!({
                "alarm_name": "alarm.elev_rejections",
                "severity": "high",
                "reason": format!(
                    "Technician '{}' received {} consecutive elevation rejections",
                    technician_id, count
                ),
                "consecutive_rejections": count,
                "threshold": self.config.elev_rejections_threshold,
                "technician_id": technician_id,
                "target_device": target_device,
                "rejection_reason": rejection_reason,
            });

            let mut input = EventInput::new(
                trace,
                Source::Api,
                Category::Alarm,
                "alarm.elev_rejections",
                actor,
                Outcome::Denied,
                details,
            );
            if let Some(subj) = subject {
                input = input.with_subject(subj);
            }

            let event = self.audit.append(input).await?;
            return Ok(Some(event));
        }

        Ok(None)
    }

    /// Resets consecutive rejections for a technician when an elevation is approved.
    pub fn record_elevation_approval(&self, technician_id: &str, target_device: Option<&str>) {
        let mut lock = self.consecutive_rejections.lock().unwrap();
        lock.remove(technician_id);
        if let Some(dev) = target_device {
            lock.remove(&format!("{}:{}", technician_id, dev));
        }
    }

    /// Records an elevation attempts exhausted alarm (`alarm.elev_exhausted`).
    ///
    /// Triggered when the 3-attempt limit for elevation credentials in a session has been reached.
    pub async fn record_elevation_exhausted(
        &self,
        technician_id: &str,
        target_device: Option<&str>,
        actor_ip: Option<&str>,
        attempts: usize,
        trace_id: Option<&str>,
    ) -> Result<AuditEvent, AuditError> {
        let trace = trace_id
            .map(String::from)
            .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
        let actor = Actor::with_details(
            technician_id,
            "user",
            Some(technician_id.to_string()),
            actor_ip.map(String::from),
        );
        let subject = target_device.map(|dev| Subject::with_details(dev, "device", None));

        let details = json!({
            "alarm_name": "alarm.elev_exhausted",
            "severity": "critical",
            "reason": format!(
                "Session elevation attempts exhausted for technician '{}' (limit: {} attempts reached)",
                technician_id, attempts
            ),
            "attempts": attempts,
            "technician_id": technician_id,
            "target_device": target_device,
            "lockout_action": "session_elevation_disabled",
        });

        let mut input = EventInput::new(
            trace,
            Source::Api,
            Category::Alarm,
            "alarm.elev_exhausted",
            actor,
            Outcome::Denied,
            details,
        );
        if let Some(subj) = subject {
            input = input.with_subject(subj);
        }

        self.audit.append(input).await
    }

    /// Checks if an elevation action occurred outside configured business hours.
    ///
    /// If after hours, records an `alarm.elev_after_hours` event in `AuditStore`
    /// and returns `Some(event)`.
    pub async fn check_elevation_after_hours(
        &self,
        technician_id: &str,
        action: &str,
        target_device: Option<&str>,
        actor_ip: Option<&str>,
        timestamp: Option<DateTime<Utc>>,
        trace_id: Option<&str>,
    ) -> Result<Option<AuditEvent>, AuditError> {
        let dt = timestamp.unwrap_or_else(Utc::now);
        if !self.is_after_hours(&dt) {
            return Ok(None);
        }

        let trace = trace_id
            .map(String::from)
            .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
        let actor = Actor::with_details(
            technician_id,
            "user",
            Some(technician_id.to_string()),
            actor_ip.map(String::from),
        );
        let subject = target_device.map(|dev| Subject::with_details(dev, "device", None));

        let details = json!({
            "alarm_name": "alarm.elev_after_hours",
            "severity": "medium",
            "reason": format!(
                "Elevation operation '{}' requested or executed outside configured business hours",
                action
            ),
            "action": action,
            "timestamp": dt.to_rfc3339(),
            "business_hours_start": self.config.elev_business_hours_start,
            "business_hours_end": self.config.elev_business_hours_end,
            "technician_id": technician_id,
            "target_device": target_device,
        });

        let mut input = EventInput::new(
            trace,
            Source::Api,
            Category::Alarm,
            "alarm.elev_after_hours",
            actor,
            Outcome::Denied,
            details,
        );
        if let Some(subj) = subject {
            input = input.with_subject(subj);
        }

        let event = self.audit.append(input).await?;
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

        // 4. Elevation events evaluation (F3-17)
        if event.category == Category::Elev {
            let target_device = event.subject.as_ref().map(|s| s.id.as_str());
            let technician_id = event.actor.id.as_str();
            let actor_ip = event.actor.ip.as_deref();
            let trace = Some(event.trace_id.as_str());
            let event_dt = event.ts.parse::<DateTime<Utc>>().ok();

            // A. After-hours check for requested or executed
            if event.action == "elev.requested" || event.action == "elev.executed" {
                if let Some(alarm) = self
                    .check_elevation_after_hours(
                        technician_id,
                        &event.action,
                        target_device,
                        actor_ip,
                        event_dt,
                        trace,
                    )
                    .await?
                {
                    triggered.push(alarm);
                }
            }

            // B. Frequency tracking on requests and executions
            if event.action == "elev.requested" || event.action == "elev.executed" {
                if let Some(alarm) = self
                    .record_elevation_attempt(
                        technician_id,
                        target_device,
                        actor_ip,
                        trace,
                        event_dt,
                    )
                    .await?
                {
                    triggered.push(alarm);
                }
            }

            // C. Consecutive rejections vs approval reset
            if event.action == "elev.rejected" {
                let rejection_reason = event
                    .details
                    .get("rejection_reason")
                    .and_then(|v| v.as_str());
                if let Some(alarm) = self
                    .record_elevation_rejection(
                        technician_id,
                        target_device,
                        actor_ip,
                        trace,
                        rejection_reason,
                    )
                    .await?
                {
                    triggered.push(alarm);
                }
            } else if event.action == "elev.approved" {
                self.record_elevation_approval(technician_id, target_device);
            }

            // D. Exhausted attempts
            if event.action == "elev.exhausted" {
                let attempts = event
                    .details
                    .get("attempts")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(3) as usize;
                let alarm = self
                    .record_elevation_exhausted(
                        technician_id,
                        target_device,
                        actor_ip,
                        attempts,
                        trace,
                    )
                    .await?;
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

    #[test]
    fn test_is_after_hours_evaluation() {
        let config = AlarmConfig {
            elev_after_hours_enabled: true,
            elev_business_hours_start: 7,
            elev_business_hours_end: 19,
            elev_weekends_are_after_hours: true,
            ..Default::default()
        };

        // Tuesday 10:00 UTC -> during business hours
        let dt_workday_day: DateTime<Utc> = "2026-11-10T10:00:00Z".parse().unwrap();
        // Tuesday 05:00 UTC -> before business hours (after-hours)
        let dt_workday_early: DateTime<Utc> = "2026-11-10T05:00:00Z".parse().unwrap();
        // Tuesday 21:00 UTC -> after business hours
        let dt_workday_night: DateTime<Utc> = "2026-11-10T21:00:00Z".parse().unwrap();
        // Saturday 12:00 UTC -> weekend (after-hours)
        let dt_saturday: DateTime<Utc> = "2026-11-14T12:00:00Z".parse().unwrap();

        // Helper mock engine
        use chrono::{Datelike, Timelike, Weekday};
        let is_after = |dt: &DateTime<Utc>| -> bool {
            if config.elev_weekends_are_after_hours {
                let weekday = dt.weekday();
                if weekday == Weekday::Sat || weekday == Weekday::Sun {
                    return true;
                }
            }
            let hour = dt.hour();
            hour < config.elev_business_hours_start || hour >= config.elev_business_hours_end
        };

        assert!(!is_after(&dt_workday_day));
        assert!(is_after(&dt_workday_early));
        assert!(is_after(&dt_workday_night));
        assert!(is_after(&dt_saturday));
    }
}
