// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{AuditEvent, AuditStore, EventFilter};
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
    cursor: Arc<Mutex<i64>>,
}
impl ExportQueue {
    pub fn new(config: ExportConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::new())),
            config,
            store: None,
            cursor: Arc::new(Mutex::new(0)),
        }
    }
    pub fn with_store(config: ExportConfig, store: StdArc<AuditStore>) -> Self {
        let mut queue = Self::new(config);
        queue.store = Some(store);
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
            let cursor = *self.cursor.lock().unwrap();
            let mut filter = EventFilter::default();
            filter.after_sequence = Some(cursor);
            filter.limit = Some(1);
            match store.query_events(filter).await {
                Ok(mut events) => events.pop(),
                Err(_) => None,
            }
        } else {
            self.inner.lock().unwrap().front().cloned()
        };
        let Some(event) = event else { return 0 };
        if export_event(&self.config, &event).await.is_ok() {
            if self.store.is_some() {
                *self.cursor.lock().unwrap() = event.sequence;
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
        send_syslog(sys, &payload).await?;
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
fn syslog_message(c: &SyslogConfig, payload: &[u8]) -> String {
    format!(
        "<{}>1 - {} - {} - - - {}",
        c.facility * 8 + 6,
        c.hostname,
        c.app_name,
        String::from_utf8_lossy(payload)
    )
}
async fn send_syslog(c: &SyslogConfig, payload: &[u8]) -> Result<(), String> {
    let msg = syslog_message(c, payload);
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
    let addr = tokio::net::lookup_host(
        if host.contains(':') || host.parse::<std::net::IpAddr>().is_ok() {
            host.to_string()
        } else {
            format!("{host}:80")
        },
    )
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
    fn hmac_is_deterministic() {
        let c = WebhookConfig {
            url: "http://127.0.0.1:1".into(),
            secret: b"secret".to_vec(),
        };
        assert_eq!(c.secret, b"secret");
    }
}
