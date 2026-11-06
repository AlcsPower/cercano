// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{AuditEvent, AuditStore, EventFilter};
use chrono::{DateTime, SecondsFormat, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::VecDeque;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc as StdArc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

#[derive(Debug, Clone)]
pub struct WebhookConfig {
    pub url: String,
    pub secret: Vec<u8>,
}
#[derive(Debug, Clone)]
pub struct SyslogConfig {
    pub destination: SocketAddr,
    pub transport: SyslogTransport,
    pub facility: u8,
    pub hostname: String,
    pub app_name: String,
}
#[derive(Debug, Clone)]
pub enum SyslogTransport {
    Udp,
    Tcp,
    Tls,
}
#[derive(Debug, Clone)]
pub struct ExportConfig {
    pub syslog: Option<SyslogConfig>,
    pub webhook: Option<WebhookConfig>,
    pub jsonl_path: Option<PathBuf>,
    pub max_queue: usize,
    pub retry_delay: Duration,
}

#[derive(Clone)]
pub struct ExportQueue {
    inner: Arc<Mutex<VecDeque<AuditEvent>>>,
    config: ExportConfig,
    store: Option<StdArc<AuditStore>>,
    cursor: Arc<Mutex<Option<i64>>>,
}
impl ExportQueue {
    pub fn new(config: ExportConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::new())),
            config,
            store: None,
            cursor: Arc::new(Mutex::new(None)),
        }
    }
    pub fn with_store(config: ExportConfig, store: StdArc<AuditStore>) -> Self {
        let mut queue = Self::new(config);
        queue.store = Some(store.clone());
        queue
    }
    pub fn enqueue(&self, event: AuditEvent) -> bool {
        let mut q = self.inner.lock().unwrap();
        if q.len() >= self.config.max_queue {
            return false;
        }
        q.push_back(event);
        true
    }
    pub fn pending(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
    pub async fn flush_once(&self) -> usize {
        let event = if let Some(store) = &self.store {
            let cached_cursor = { *self.cursor.lock().unwrap() };
            let cursor = match cached_cursor {
                Some(cursor) => cursor,
                None => match store.load_export_cursor().await {
                    Ok(cursor) => {
                        *self.cursor.lock().unwrap() = Some(cursor);
                        cursor
                    }
                    Err(_) => return 0,
                },
            };
            let filter = EventFilter {
                after_sequence: Some(cursor),
                limit: Some(1),
                ..Default::default()
            };
            match store.query_events(filter).await {
                Ok(mut events) => events.pop(),
                Err(_) => None,
            }
        } else {
            self.inner.lock().unwrap().front().cloned()
        };
        let Some(event) = event else { return 0 };
        if export_event(&self.config, &event).await.is_ok() {
            if let Some(store) = &self.store {
                if store.save_export_cursor(event.sequence).await.is_err() {
                    return 0;
                }
                *self.cursor.lock().unwrap() = Some(event.sequence);
            } else {
                self.inner.lock().unwrap().pop_front();
            }
            1
        } else {
            0
        }
    }
    pub async fn flush_until_empty(&self) {
        while self.flush_once().await > 0 {}
    }
}

async fn export_event(config: &ExportConfig, event: &AuditEvent) -> Result<(), String> {
    let payload = serde_json::to_vec(event).map_err(|e| e.to_string())?;
    if let Some(sys) = &config.syslog {
        send_syslog(sys, &event.ts, &payload).await?;
    }
    if let Some(web) = &config.webhook {
        send_webhook(web, &payload).await?;
    }
    if let Some(path) = &config.jsonl_path {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        f.write_all(&payload)
            .and_then(|_| f.write_all(b"\n"))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
fn syslog_message(c: &SyslogConfig, ts: &str, payload: &[u8]) -> String {
    let timestamp = DateTime::parse_from_rfc3339(ts)
        .map(|value| {
            value
                .with_timezone(&Utc)
                .to_rfc3339_opts(SecondsFormat::Millis, true)
        })
        .unwrap_or_else(|_| ts.to_string());
    format!(
        "<{}>1 {} {} {} - - - {}",
        c.facility * 8 + 6,
        timestamp,
        c.hostname,
        c.app_name,
        String::from_utf8_lossy(payload)
    )
}
async fn send_syslog(c: &SyslogConfig, ts: &str, payload: &[u8]) -> Result<(), String> {
    let msg = syslog_message(c, ts, payload);
    match c.transport {
        SyslogTransport::Udp => {
            let s = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| e.to_string())?;
            s.send_to(msg.as_bytes(), c.destination)
                .await
                .map_err(|e| e.to_string())?;
        }
        SyslogTransport::Tcp => {
            let mut s = TcpStream::connect(c.destination)
                .await
                .map_err(|e| e.to_string())?;
            s.write_all(msg.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
        }
        SyslogTransport::Tls => {
            return Err(
                "Syslog TLS requiere configuración de certificado y aún no está disponible"
                    .to_string(),
            );
        }
    }
    Ok(())
}
async fn send_webhook(c: &WebhookConfig, payload: &[u8]) -> Result<(), String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&c.secret).map_err(|e| e.to_string())?;
    mac.update(payload);
    let sig = hex::encode(mac.finalize().into_bytes());
    let u = c
        .url
        .strip_prefix("http://")
        .ok_or_else(|| "only http webhook supported".to_string())?;
    let (host, path) = match u.split_once('/') {
        Some((h, p)) => (h, format!("/{}", p)),
        None => (u, "/".to_string()),
    };
    let host_for_lookup = if host.contains(':') {
        host.to_string()
    } else {
        format!("{host}:80")
    };
    let addr = tokio::net::lookup_host(host_for_lookup)
        .await
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| "webhook host did not resolve".to_string())?;
    let mut s = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let req = format!("POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Cercano-Signature: sha256={}\r\nConnection: close\r\n\r\n", path, host, payload.len(), sig);
    s.write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    s.write_all(payload).await.map_err(|e| e.to_string())?;
    let mut response = [0_u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut response))
        .await
        .map_err(|_| "webhook response timeout".to_string())?
        .map_err(|e| e.to_string())?;
    if n < 12 || !response.starts_with(b"HTTP/1.1 2") {
        return Err("webhook rejected event".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hmac_sha256_known_vector() {
        let mut mac = Hmac::<Sha256>::new_from_slice(b"key").unwrap();
        mac.update(b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            hex::encode(mac.finalize().into_bytes()),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn syslog_message_uses_event_timestamp() {
        let config = SyslogConfig {
            destination: "127.0.0.1:514".parse().unwrap(),
            transport: SyslogTransport::Udp,
            facility: 1,
            hostname: "host".into(),
            app_name: "cercano".into(),
        };
        assert_eq!(
            syslog_message(&config, "2026-01-02T03:04:05.678+02:00", b"{}"),
            "<14>1 2026-01-02T01:04:05.678Z host cercano - - - {}"
        );
    }

    #[tokio::test]
    async fn udp_syslog_contains_rfc5424_header_and_event_timestamp() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = SyslogConfig {
            destination: receiver.local_addr().unwrap(),
            transport: SyslogTransport::Udp,
            facility: 1,
            hostname: "host".into(),
            app_name: "cercano".into(),
        };
        send_syslog(&config, "2026-01-02T03:04:05Z", br#"{"action":"test"}"#)
            .await
            .unwrap();
        let mut buf = [0; 512];
        let (len, _) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&buf[..len]).unwrap(),
            "<14>1 2026-01-02T03:04:05.000Z host cercano - - - {\"action\":\"test\"}"
        );
    }
}
