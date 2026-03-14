// firewallx/src/modules/siem.rs
// External SIEM Logging Dispatcher (Elasticsearch, Splunk, Datadog)

use std::sync::mpsc::{self, Sender, Receiver};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::Serialize;
use reqwest::blocking::Client;

#[derive(Debug, Serialize, Clone)]
pub struct SiemEvent {
    pub timestamp: u64,
    pub event_type: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub message: String,
    pub action_taken: String,
}

impl SiemEvent {
    pub fn new(
        event_type: &str,
        src_ip: &str,
        dst_ip: &str,
        dst_port: u16,
        protocol: &str,
        message: &str,
        action_taken: &str,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            timestamp,
            event_type: event_type.to_string(),
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            dst_port,
            protocol: protocol.to_string(),
            message: message.to_string(),
            action_taken: action_taken.to_string(),
        }
    }
}

/// A non-blocking asynchronous dispatcher for SIEM endpoints.
/// We use an MPSC channel so the FirewallEngine never stalls on HTTP requests.
pub struct SiemLogger {
    sender: Sender<SiemEvent>,
}

impl SiemLogger {
    pub fn new(endpoint_url: String, api_key: Option<String>) -> Self {
        let (tx, rx): (Sender<SiemEvent>, Receiver<SiemEvent>) = mpsc::channel();
        
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap_or_else(|_| Client::new());

        // Spawn background worker thread
        thread::spawn(move || {
            for event in rx {
                // In a production environment with high throughput, we'd batch these up.
                // For this model, we dispatch per-event for immediate reflection.
                let mut req = client.post(&endpoint_url).json(&event);
                
                if let Some(ref key) = api_key {
                    req = req.header("Authorization", format!("Bearer {}", key));
                }
                
                // Fire and forget - fail silently to prevent crashing the SIEM pipeline
                let _ = req.send();
            }
        });

        Self { sender: tx }
    }

    /// Queues an event to be sent to the external SIEM. Returns instantly.
    pub fn log(&self, event: SiemEvent) {
        let _ = self.sender.send(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_siem_event_serialization() {
        let ev = SiemEvent::new(
            "DPI_BLOCK",
            "10.0.0.5",
            "192.168.1.100",
            80,
            "TCP",
            "SQL Injection payload detected",
            "Drop"
        );
        let serialized = serde_json::to_string(&ev).unwrap();
        assert!(serialized.contains(r#""event_type":"DPI_BLOCK""#));
        assert!(serialized.contains(r#""message":"SQL Injection payload detected""#));
    }
}
