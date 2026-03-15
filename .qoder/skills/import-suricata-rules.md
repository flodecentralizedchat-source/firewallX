# Import and Convert Suricata Rules

Parse Suricata/Snort signature files and convert them into native FirewallX DPI engine rules with proper signature matching and alert configuration.

## Purpose

Automate the migration of existing IDS/IPS signatures from Suricata and Snort formats into FirewallX's DPI engine, enabling rapid deployment of thousands of pre-built threat detection rules.

## Supported Rule Formats

### 1. Suricata Format

```suricata
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (
    msg:"ET WEB_SPECIFIC_APPS WordPress Login Attempt";
    flow:to_server,established;
    content:"POST";
    http_method;
    content:"/wp-login.php";
    http_uri;
    content:"username=";
    http_client_body;
    classtype:web-application-attack;
    sid:2024567;
    rev:1;
)
```

### 2. Snort Format

```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET 443 (
    msg:"POLICY Other SSL/TLS Certificate Self-Signed";
    flow:to_server,established;
    content:"|16 03|";
    depth:2;
    content:"|01 00|";
    within:3;
    reference:url,www.example.com;
    classtype:policy-violation;
    sid:1234567;
    rev:3;
)
```

### 3. Emerging Threats Format

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"ET MALWARE Win32/Agent Tesla CnC Beacon";
    flow:established,to_server;
    http.method;
    content:"POST";
    http.uri;
    content:"application/x-www-form-urlencoded";
    http.content_type;
    pcre:"/^POST\s\/gate\.php\sHTTP\/1\.[01]$/H";
    reference:url,otx.alienvault.com;
    classtype:trojan-activity;
    sid:2034567;
    rev:2;
)
```

## Conversion Process

### Step 1: Parse Rule Structure

Extract components from source rule:

```rust
struct SuricataRule {
    action: String,        // alert, pass, drop, reject
    protocol: String,      // tcp, udp, http, dns, etc.
    src_network: String,   // $EXTERNAL_NET, IP ranges
    src_port: String,      // any, specific ports
    dst_network: String,   // $HOME_NET
    dst_port: String,      // 80, 443, any
    direction: String,     // -> or <>
    options: RuleOptions,  // All rule options
}

struct RuleOptions {
    msg: Option<String>,           // Rule description
    flow: Option<String>,          // Flow characteristics
    content: Vec<ContentMatch>,    // Content matches
    pcre: Option<PcreMatch>,       // Regex patterns
    classtype: Option<String>,     // Classification
    sid: u32,                      // Signature ID
    rev: u32,                      // Revision
    reference: Vec<Reference>,     // External references
}
```

### Step 2: Map to FirewallX DPI Engine

Convert Suricata options to FirewallX constructs:

```rust
impl From<SuricataRule> for firewallx::DpiSignature {
    fn from(suri: SuricataRule) -> Self {
        let action = match suri.action.as_str() {
            "drop" | "reject" => Action::Drop,
            "alert" => Action::Alert,
            "pass" => Action::Allow,
            _ => Action::Alert,
        };

        let mut sig = firewallx::DpiSignature::new(
            suri.options.sid,
            &suri.options.msg.unwrap_or_default(),
            action,
        );

        // Map content matches
        for content in suri.options.content {
            if content.http_field.is_some() {
                // HTTP-specific inspection
                sig.add_http_match(
                    content.http_field.unwrap(),
                    content.pattern,
                );
            } else {
                // Generic payload match
                sig.add_pattern(&content.pattern);
            }
        }

        // Map PCRE regex patterns
        if let Some(pcre) = suri.options.pcre {
            sig.add_regex(&pcre.pattern)?;
        }

        // Map flow characteristics
        if let Some(flow) = suri.options.flow {
            if flow.contains("to_server") {
                sig.set_direction(Direction::Inbound);
            }
            if flow.contains("established") {
                sig.require_state(State::Established);
            }
        }

        // Set protocol
        sig.set_protocol(parse_protocol(&suri.protocol));

        // Add classification as metadata
        if let Some(classtype) = suri.options.classtype {
            sig.add_metadata("classtype", &classtype);
        }

        Ok(sig)
    }
}
```

### Step 3: Generate FirewallX Configuration

Output converted rules:

```toml
# Converted from Suricata rule SID:2024567
[[dpi_signatures]]
id = 2024567
name = "ET WEB_SPECIFIC_APPS WordPress Login Attempt"
action = "alert"
protocol = "tcp"
direction = "inbound"
port = 80

# Content matches
[[dpi_signatures.matches]]
type = "http_method"
pattern = "POST"

[[dpi_signatures.matches]]
type = "http_uri"
pattern = "/wp-login.php"

[[dpi_signatures.matches]]
type = "http_client_body"
pattern = "username="

[metadata]
classtype = "web-application-attack"
source = "emerging_threats"
revision = 1
```

## CLI Usage

### Import Single File

```bash
# Convert a single .rules file
firewallx rule import --file /path/to/emerging-threats.rules

# Output:
# Successfully imported 1,247 Suricata signatures from /path/to/emerging-threats.rules
# - Web attacks: 423
# - Malware: 312
# - Policy violations: 198
# - Exploit attempts: 314
```

### Import Multiple Files

```bash
# Batch import all rules files in directory
for file in /opt/suricata-rules/*.rules; do
    firewallx rule import --file "$file"
done
```

### Preview Before Import

```bash
# Analyze rules without importing
firewallx rule import --file rules.rules --dry-run

# Output:
# Analysis of rules.rules:
# Total signatures: 1,247
# Unsupported features: 23 (PCRE with backtracking)
# Will convert: 1,224 signatures
# Estimated memory footprint: ~12MB
```

### Export Converted Rules

```bash
# Export converted rules to config file
firewallx rule export --format toml --output dpi-signatures.toml

# Or export as JSON for API integration
firewallx rule export --format json --pretty --output signatures.json
```

## Advanced Conversions

### 1. HTTP Field Mapping

Suricata HTTP keywords → FirewallX DPI matches:

| Suricata Keyword | FirewallX Match Type | Description |
|------------------|---------------------|-------------|
| `http_method` | `http.method` | HTTP method (GET, POST, etc.) |
| `http_uri` | `http.uri` | Request URI path |
| `http_header` | `http.header` | Specific header name/value |
| `http_host` | `http.host` | Host header value |
| `http_client_body` | `http.body` | Request body content |
| `http_stat_code` | `http.status_code` | Response status code |
| `http_content_type` | `http.content_type` | Content-Type header |

**Example:**

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Suspicious POST to suspicious endpoint";
    http.method;
    content:"POST";
    http.uri;
    content:"/api/upload";
    http.content_type;
    content:"multipart/form-data";
)
```

Converted to FirewallX:

```rust
let mut sig = DpiSignature::new(1001, "Suspicious POST upload", Action::Alert);
sig.add_http_match(HttpField::Method, "POST");
sig.add_http_match(HttpField::Uri, "/api/upload");
sig.add_http_match(HttpField::ContentType, "multipart/form-data");
```

### 2. PCRE Regex Conversion

Suricata PCRE patterns → Rust regex:

```suricata
# Suricata PCRE
pcre:"/^GET\s\/admin\S*\.php\sHTTP\/1\.[01]$/H";
```

```rust
// FirewallX (Rust regex)
use regex::Regex;
let pattern = Regex::new(r"^GET\s/admin\S*\.php\sHTTP/1\.[01]$").unwrap();
sig.add_regex(pattern);
```

**Limitations:**
- ❌ PCRE backtracking not supported in Rust regex
- ❌ Lookbehind assertions limited
- ✅ Most standard patterns work identically
- ✅ Unicode support enabled by default

### 3. Byte Matching

Suricata byte extraction → FirewallX:

```suricata
# Extract bytes at offset
byte_test:2,>,30000,0,offset=0,relative;
```

```rust
// FirewallX equivalent
sig.add_byte_check(ByteCheck {
    size: 2,              // bytes to extract
    operator: Op::Greater,
    value: 30000,
    offset: 0,
    endian: Endian::Big,
});
```

## Validation & Testing

### Test Individual Signatures

```bash
# Test signature against sample payload
firewallx dpi test \
  --signature-id 2024567 \
  --payload "POST /wp-login.php HTTP/1.1\r\nusername=admin"

# Output:
# ✓ MATCH - Signature 2024567 triggered
# Action: ALERT
# Message: ET WEB_SPECIFIC_APPS WordPress Login Attempt
```

### Validate All Imported Rules

```bash
# Syntax check all signatures
firewallx dpi validate

# Output:
# Validating 1,247 signatures...
# ✓ All signatures valid
# Warnings:
# - Signature 2034567: Complex regex may impact performance
# - Signature 2045678: Large pattern (>1KB)
```

### Performance Benchmarking

```bash
# Benchmark signature evaluation speed
firewallx dpi benchmark \
  --iterations 100000 \
  --sample-payloads /opt/test-payloads/

# Output:
# Average latency: 2.3μs per packet
# Throughput: 434,782 packets/sec
# Memory usage: 12.4MB
# False positive rate: 0.003%
```

## Optimization Strategies

### 1. Signature Grouping

Group related signatures for efficient evaluation:

```rust
// Instead of checking each signature individually:
for sig in signatures {
    if sig.matches(payload) { alert(sig); }
}

// Group by port/protocol first:
let relevant = signatures_by_port.get(80).unwrap();
for sig in relevant {
    if sig.matches(payload) { alert(sig); }
}

// Reduces checks from 10,000 to ~50 per packet
```

### 2. Multi-Pattern Matching

Use Aho-Corasick algorithm for multiple string matches:

```rust
use aho_corasick::AhoCorasick;

let patterns = vec!["<script>", "SELECT * FROM", "../etc/passwd"];
let ac = AhoCorasick::new(patterns);

// Single pass finds all matches
for mat in ac.find_iter(payload) {
    alert_signature(mat.pattern());
}
```

### 3. Lazy Compilation

Compile expensive regexes on-demand:

```rust
lazy_static! {
    static ref EXPENSIVE_REGEX: Regex = 
        Regex::new(r"(complex|pattern|with|many|alternations)").unwrap();
}

// Only compiled once, reused thereafter
if EXPENSIVE_REGEX.is_match(payload) {
    trigger_alert();
}
```

## Troubleshooting

### Problem: Rule Fails to Match

**Debugging steps:**

```bash
# Enable verbose logging
export RUST_LOG=firewallx::dpi=debug
firewallx start

# Check what's being inspected
firewallx logs --grep "DPI" --since 1m

# Verify payload contains expected pattern
echo "test payload" | xxd
```

### Problem: Too Many False Positives

**Solutions:**
1. Increase specificity with additional content matches
2. Add flow requirements (established connections only)
3. Implement threshold limiting (alert max once per minute)
4. Whitelist trusted sources

```toml
# Add threshold to signature
[[dpi_signatures]]
id = 2024567
# ... other fields ...

[threshold]
type = "limit"
count = 1
seconds = 60
track = "by_src"
```

### Problem: Performance Degradation

**Optimize:**

```bash
# Profile which signatures are slowest
firewallx dpi profile --duration 60

# Output shows top 10 slowest:
# Rank  SigID    Avg Time  Count  Name
# 1     2034567  15.2μs    1234   Complex PCRE malware signature
# 2     2045678  12.8μs    567    Large multi-pattern exploit

# Disable or optimize problematic signatures
firewallx rule disable --sid 2034567
```

## Integration with Threat Feeds

### Subscribe to Emerging Threats

```bash
# Add Emerging Threats Open feed
firewallx feed add https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz

# Automatically fetch and update weekly
firewallx feed update --interval weekly

# View subscribed feeds
firewallx feed list
```

### Custom Feed Management

```bash
# Create custom blocklist from SIEM data
cat malicious_ips.txt | while read ip; do
    firewallx rule add \
      --name "SIEM identified threat" \
      --action drop \
      --src_ip "$ip" \
      --protocol any \
      --direction inbound
done
```
