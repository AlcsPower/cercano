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
pub const DEFAULT_INTERNAL_TOKEN: &str = "cercano_internal_token_secret";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub log_level: String,
    pub device_grace_period_secs: u64,
    pub server_key_path: String,
    pub internal_token: String,
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
            internal_token: DEFAULT_INTERNAL_TOKEN.to_string(),
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
        assert_eq!(cfg.internal_token, "cercano_internal_token_secret");
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

        let mut cfg = Config::default();
        cfg.merge_env().unwrap();

        assert_eq!(cfg.host, "192.168.1.100");
        assert_eq!(cfg.port, 22000);
        assert_eq!(cfg.database_url, "sqlite://env_test.db");
        assert_eq!(cfg.log_level, "warn");
        assert_eq!(cfg.device_grace_period_secs, 45);
        assert_eq!(cfg.server_key_path, "/env/path/id_ed25519.pub");

        env::remove_var("CERCANO_HOST");
        env::remove_var("CERCANO_PORT");
        env::remove_var("CERCANO_DATABASE_URL");
        env::remove_var("CERCANO_LOG_LEVEL");
        env::remove_var("CERCANO_DEVICE_GRACE_PERIOD_SECS");
        env::remove_var("CERCANO_SERVER_KEY_PATH");
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
