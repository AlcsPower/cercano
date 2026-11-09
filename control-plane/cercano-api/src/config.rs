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

use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;

pub const DEFAULT_HOST: &str = "0.0.0.0";
pub const DEFAULT_PORT: u16 = 21114;
pub const DEFAULT_DB_PATH: &str = "sqlite://cercano.db?mode=rwc";
pub const DEFAULT_LOG_LEVEL: &str = "info";
pub const DEFAULT_DEVICE_GRACE_PERIOD_SECS: u64 = 60;
pub const DEFAULT_SERVER_KEY_PATH: &str = "/opt/cercano/data/id_ed25519.pub";
pub const DEFAULT_AUDIT_KEY_PATH: &str = "/opt/cercano/data/audit_signing_key";
pub const DEFAULT_CHECKPOINT_INTERVAL_SECS: u64 = 300;
pub const DEFAULT_BUILDS_DIR: &str = "./data/builds";
pub const DEFAULT_BUILD_CONCURRENCY: usize = 2;
pub const DEFAULT_BUILD_RETENTION_SECS: u64 = 7 * 24 * 3600;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub log_level: String,
    pub device_grace_period_secs: u64,
    pub server_key_path: String,
    /// Shared secret for server-side audit ingestion. Empty means "not configured" and ingestion
    /// through this channel is refused; the API refuses to start without it (see main).
    pub internal_token: String,
    /// Dedicated shared secret for client-side audit ingestion (/api/audit/conn, /api/audit/file,
    /// /api/audit/alarm). Rejection from generic ingestion endpoints prevents clients from forging
    /// admin or server events.
    pub client_ingest_token: String,
    /// Proxies whose X-Forwarded-For header is trusted (CIDR or exact IP).
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub ip_whitelist: Vec<String>,
    pub audit_key_path: String,
    pub audit_checkpoint_interval_secs: u64,
    #[serde(default = "default_builds_dir")]
    pub builds_dir: String,
    #[serde(default = "default_build_concurrency")]
    pub build_concurrency: usize,
    #[serde(default = "default_build_retention_secs")]
    pub build_retention_secs: u64,
    #[serde(default)]
    pub build_signing_key_path: Option<String>,
}

fn default_builds_dir() -> String {
    DEFAULT_BUILDS_DIR.to_string()
}

fn default_build_concurrency() -> usize {
    DEFAULT_BUILD_CONCURRENCY
}

fn default_build_retention_secs() -> u64 {
    DEFAULT_BUILD_RETENTION_SECS
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: DEFAULT_HOST.to_string(),
            port: DEFAULT_PORT,
            database_url: DEFAULT_DB_PATH.to_string(),
            log_level: DEFAULT_LOG_LEVEL.to_string(),
            device_grace_period_secs: DEFAULT_DEVICE_GRACE_PERIOD_SECS,
            server_key_path: DEFAULT_SERVER_KEY_PATH.to_string(),
            internal_token: String::new(),
            client_ingest_token: String::new(),
            trusted_proxies: vec!["127.0.0.1/32".to_string(), "::1/128".to_string()],
            ip_whitelist: Vec::new(),
            audit_key_path: DEFAULT_AUDIT_KEY_PATH.to_string(),
            audit_checkpoint_interval_secs: DEFAULT_CHECKPOINT_INTERVAL_SECS,
            builds_dir: DEFAULT_BUILDS_DIR.to_string(),
            build_concurrency: DEFAULT_BUILD_CONCURRENCY,
            build_retention_secs: DEFAULT_BUILD_RETENTION_SECS,
            build_signing_key_path: None,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct FileConfig {
    host: Option<String>,
    port: Option<u16>,
    database_url: Option<String>,
    db_path: Option<String>,
    log_level: Option<String>,
    device_grace_period_secs: Option<u64>,
    server_key_path: Option<String>,
    internal_token: Option<String>,
    client_ingest_token: Option<String>,
    trusted_proxies: Option<Vec<String>>,
    ip_whitelist: Option<Vec<String>>,
    audit_key_path: Option<String>,
    audit_checkpoint_interval_secs: Option<u64>,
    builds_dir: Option<String>,
    build_concurrency: Option<usize>,
    build_retention_secs: Option<u64>,
    build_signing_key_path: Option<String>,
}

impl Config {
    /// Loads configuration by checking:
    /// 1. Default values
    /// 2. Config file (if specified via CERCANO_CONFIG_PATH or default `cercano.toml` if present)
    /// 3. Environment variables (CERCANO_HOST, CERCANO_PORT, CERCANO_DATABASE_URL/CERCANO_DB_PATH, CERCANO_LOG_LEVEL, CERCANO_DEVICE_GRACE_PERIOD_SECS)
    pub fn load() -> Result<Self, String> {
        let mut config = Self::default();

        let config_file_path = env::var("CERCANO_CONFIG_PATH").ok();
        if let Some(path) = config_file_path {
            config.merge_file(&path)?;
        } else if Path::new("cercano.toml").exists() {
            config.merge_file("cercano.toml")?;
        }

        config.merge_env()?;
        Ok(config)
    }

    /// Merges configuration from a TOML file.
    pub fn merge_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), String> {
        let content = fs::read_to_string(path.as_ref()).map_err(|e| {
            format!(
                "Failed to read config file {}: {}",
                path.as_ref().display(),
                e
            )
        })?;

        let file_cfg: FileConfig = toml::from_str(&content).map_err(|e| {
            format!(
                "Failed to parse config file {}: {}",
                path.as_ref().display(),
                e
            )
        })?;

        if let Some(host) = file_cfg.host {
            self.host = host;
        }
        if let Some(port) = file_cfg.port {
            self.port = port;
        }
        if let Some(db_url) = file_cfg.database_url {
            self.database_url = db_url;
        } else if let Some(db_path) = file_cfg.db_path {
            self.database_url = normalize_db_url(&db_path);
        }
        if let Some(level) = file_cfg.log_level {
            self.log_level = level;
        }
        if let Some(secs) = file_cfg.device_grace_period_secs {
            self.device_grace_period_secs = secs;
        }
        if let Some(key_path) = file_cfg.server_key_path {
            self.server_key_path = key_path;
        }
        if let Some(token) = file_cfg.internal_token {
            self.internal_token = token;
        }
        if let Some(token) = file_cfg.client_ingest_token {
            self.client_ingest_token = token;
        }
        if let Some(whitelist) = file_cfg.ip_whitelist {
            self.ip_whitelist = whitelist;
        }
        if let Some(proxies) = file_cfg.trusted_proxies {
            self.trusted_proxies = proxies;
        }
        if let Some(path) = file_cfg.audit_key_path {
            self.audit_key_path = path;
        }
        if let Some(secs) = file_cfg.audit_checkpoint_interval_secs {
            self.audit_checkpoint_interval_secs = secs;
        }
        if let Some(dir) = file_cfg.builds_dir {
            self.builds_dir = dir;
        }
        if let Some(concurrency) = file_cfg.build_concurrency {
            self.build_concurrency = concurrency;
        }
        if let Some(retention) = file_cfg.build_retention_secs {
            self.build_retention_secs = retention;
        }
        if let Some(key_path) = file_cfg.build_signing_key_path {
            self.build_signing_key_path = Some(key_path);
        }

        Ok(())
    }

    /// Merges configuration from environment variables.
    pub fn merge_env(&mut self) -> Result<(), String> {
        if let Ok(host) = env::var("CERCANO_HOST") {
            if !host.trim().is_empty() {
                self.host = host.trim().to_string();
            }
        }

        if let Ok(port_str) = env::var("CERCANO_PORT") {
            let port = port_str
                .parse::<u16>()
                .map_err(|e| format!("Invalid CERCANO_PORT '{}': {}", port_str, e))?;
            self.port = port;
        }

        if let Ok(db_url) = env::var("CERCANO_DATABASE_URL") {
            if !db_url.trim().is_empty() {
                self.database_url = db_url.trim().to_string();
            }
        } else if let Ok(db_path) = env::var("CERCANO_DB_PATH") {
            if !db_path.trim().is_empty() {
                self.database_url = normalize_db_url(db_path.trim());
            }
        }

        if let Ok(level) = env::var("CERCANO_LOG_LEVEL") {
            if !level.trim().is_empty() {
                self.log_level = level.trim().to_string();
            }
        }

        if let Ok(secs_str) = env::var("CERCANO_DEVICE_GRACE_PERIOD_SECS") {
            let secs = secs_str.parse::<u64>().map_err(|e| {
                format!(
                    "Invalid CERCANO_DEVICE_GRACE_PERIOD_SECS '{}': {}",
                    secs_str, e
                )
            })?;
            self.device_grace_period_secs = secs;
        }

        if let Ok(key_path) = env::var("CERCANO_SERVER_KEY_PATH") {
            if !key_path.trim().is_empty() {
                self.server_key_path = key_path.trim().to_string();
            }
        }

        if let Ok(token) = env::var("CERCANO_INTERNAL_TOKEN") {
            if !token.trim().is_empty() {
                self.internal_token = token.trim().to_string();
            }
        }

        if let Ok(token) = env::var("CERCANO_CLIENT_INGEST_TOKEN") {
            if !token.trim().is_empty() {
                self.client_ingest_token = token.trim().to_string();
            }
        }

        if let Ok(whitelist_str) = env::var("CERCANO_IP_WHITELIST") {
            self.ip_whitelist = whitelist_str
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
        }

        if let Ok(proxies_str) = env::var("CERCANO_TRUSTED_PROXIES") {
            self.trusted_proxies = proxies_str
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
        }

        if let Ok(path) = env::var("CERCANO_AUDIT_KEY_PATH") {
            if !path.trim().is_empty() {
                self.audit_key_path = path.trim().to_string();
            }
        }

        if let Ok(secs_str) = env::var("CERCANO_AUDIT_CHECKPOINT_INTERVAL_SECS") {
            self.audit_checkpoint_interval_secs = secs_str
                .parse::<u64>()
                .map_err(|e| format!("Invalid CERCANO_AUDIT_CHECKPOINT_INTERVAL_SECS: {}", e))?;
        }

        if let Ok(dir) = env::var("CERCANO_BUILDS_DIR") {
            if !dir.trim().is_empty() {
                self.builds_dir = dir.trim().to_string();
            }
        }

        if let Ok(concurrency_str) = env::var("CERCANO_BUILD_CONCURRENCY") {
            self.build_concurrency = concurrency_str
                .parse::<usize>()
                .map_err(|e| format!("Invalid CERCANO_BUILD_CONCURRENCY: {}", e))?;
        }

        if let Ok(retention_str) = env::var("CERCANO_BUILD_RETENTION_SECS") {
            self.build_retention_secs = retention_str
                .parse::<u64>()
                .map_err(|e| format!("Invalid CERCANO_BUILD_RETENTION_SECS: {}", e))?;
        }

        if let Ok(key_path) = env::var("CERCANO_BUILD_SIGNING_KEY_PATH") {
            if !key_path.trim().is_empty() {
                self.build_signing_key_path = Some(key_path.trim().to_string());
            }
        }

        Ok(())
    }
}

fn normalize_db_url(path: &str) -> String {
    if path.starts_with("sqlite:") {
        path.to_string()
    } else {
        format!("sqlite://{}?mode=rwc", path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;
    use tempfile::NamedTempFile;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_default_config() {
        let cfg = Config::default();
        assert_eq!(cfg.host, "0.0.0.0");
        assert_eq!(cfg.port, 21114);
        assert_eq!(cfg.database_url, "sqlite://cercano.db?mode=rwc");
        assert_eq!(cfg.log_level, "info");
        assert_eq!(cfg.device_grace_period_secs, 60);
        assert_eq!(cfg.server_key_path, "/opt/cercano/data/id_ed25519.pub");
        assert!(cfg.internal_token.is_empty());
        assert_eq!(cfg.trusted_proxies, vec!["127.0.0.1/32", "::1/128"]);
        assert_eq!(cfg.ip_whitelist, Vec::<String>::new());
        assert_eq!(cfg.audit_key_path, "/opt/cercano/data/audit_signing_key");
        assert_eq!(cfg.audit_checkpoint_interval_secs, 300);
    }

    #[test]
    fn test_merge_file() {
        let mut temp = NamedTempFile::new().unwrap();
        writeln!(
            temp,
            r#"
host = "127.0.0.1"
port = 9000
db_path = "test.db"
log_level = "debug"
device_grace_period_secs = 120
server_key_path = "/custom/keys/id_ed25519.pub"
"#
        )
        .unwrap();

        let mut cfg = Config::default();
        cfg.merge_file(temp.path()).unwrap();

        assert_eq!(cfg.host, "127.0.0.1");
        assert_eq!(cfg.port, 9000);
        assert_eq!(cfg.database_url, "sqlite://test.db?mode=rwc");
        assert_eq!(cfg.log_level, "debug");
        assert_eq!(cfg.device_grace_period_secs, 120);
        assert_eq!(cfg.server_key_path, "/custom/keys/id_ed25519.pub");
    }

    #[test]
    fn test_merge_file_with_ip_whitelist() {
        let mut temp = NamedTempFile::new().unwrap();
        writeln!(
            temp,
            r#"
ip_whitelist = ["192.168.1.0/24", "10.0.0.0/8"]
"#
        )
        .unwrap();

        let mut cfg = Config::default();
        cfg.merge_file(temp.path()).unwrap();
        assert_eq!(
            cfg.ip_whitelist,
            vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()]
        );
    }

    #[test]
    fn test_merge_file_with_database_url() {
        let mut temp = NamedTempFile::new().unwrap();
        writeln!(
            temp,
            r#"
database_url = "sqlite:///custom/path.db"
"#
        )
        .unwrap();

        let mut cfg = Config::default();
        cfg.merge_file(temp.path()).unwrap();
        assert_eq!(cfg.database_url, "sqlite:///custom/path.db");
    }

    #[test]
    fn test_merge_file_not_found() {
        let mut cfg = Config::default();
        let res = cfg.merge_file("nonexistent_path_to_config.toml");
        assert!(res.is_err());
    }

    #[test]
    fn test_normalize_db_url() {
        assert_eq!(
            normalize_db_url("my_data.db"),
            "sqlite://my_data.db?mode=rwc"
        );
        assert_eq!(normalize_db_url("sqlite://custom.db"), "sqlite://custom.db");
    }

    #[test]
    fn test_merge_env() {
        let _guard = ENV_LOCK.lock().unwrap();

        env::set_var("CERCANO_HOST", "192.168.1.100");
        env::set_var("CERCANO_PORT", "22000");
        env::set_var("CERCANO_DATABASE_URL", "sqlite://env_test.db");
        env::set_var("CERCANO_LOG_LEVEL", "warn");
        env::set_var("CERCANO_DEVICE_GRACE_PERIOD_SECS", "45");
        env::set_var("CERCANO_SERVER_KEY_PATH", "/env/path/id_ed25519.pub");
        env::set_var("CERCANO_CLIENT_INGEST_TOKEN", "client_token_test_123");

        let mut cfg = Config::default();
        cfg.merge_env().unwrap();

        assert_eq!(cfg.host, "192.168.1.100");
        assert_eq!(cfg.port, 22000);
        assert_eq!(cfg.database_url, "sqlite://env_test.db");
        assert_eq!(cfg.log_level, "warn");
        assert_eq!(cfg.device_grace_period_secs, 45);
        assert_eq!(cfg.server_key_path, "/env/path/id_ed25519.pub");
        assert_eq!(cfg.client_ingest_token, "client_token_test_123");

        env::remove_var("CERCANO_HOST");
        env::remove_var("CERCANO_PORT");
        env::remove_var("CERCANO_DATABASE_URL");
        env::remove_var("CERCANO_LOG_LEVEL");
        env::remove_var("CERCANO_DEVICE_GRACE_PERIOD_SECS");
        env::remove_var("CERCANO_SERVER_KEY_PATH");
        env::remove_var("CERCANO_CLIENT_INGEST_TOKEN");
    }

    #[test]
    fn test_merge_env_invalid_port() {
        let _guard = ENV_LOCK.lock().unwrap();

        env::set_var("CERCANO_PORT", "not_a_number");
        let mut cfg = Config::default();
        assert!(cfg.merge_env().is_err());
        env::remove_var("CERCANO_PORT");
    }
}
