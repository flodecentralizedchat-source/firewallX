# Setup AI Security Analyst Integration

Configure FirewallX's autonomous AI investigator to analyze IDS alerts, correlate attack patterns, and generate automated incident response recommendations using LLM APIs.

## Purpose

Transform raw firewall telemetry into intelligent security insights by streaming IDS/IPS alerts to Large Language Models (GPT-4, Claude, etc.) for real-time analysis, threat correlation, and automated playbook generation.

## Architecture Overview

```
┌─────────────────┐
│  FirewallX IDS  │──(Alert Stream)──▶│  Alert Queue  │
│  - Port Scans   │                    │  (mpsc chan)  │
│  - Brute Force  │                    └───────┬───────┘
│  - DDoS/Flood   │                            │
│  - DPI Matches  │                            ▼
│  - Blocklist    │              ┌─────────────────────────┐
│                │              │  AI Investigator Agent  │
└─────────────────┘              │  - Context aggregation  │
                                 │  - Pattern correlation  │
                                 │  - LLM API integration  │
                                 │  - Playbook generation  │
                                 └───────────┬─────────────┘
                                             │
                          ┌──────────────────┼──────────────────┐
                          │                  │                  │
                          ▼                  ▼                  ▼
                   ┌────────────┐    ┌────────────┐    ┌────────────┐
                   │  OpenAI    │    │  Anthropic │    │  Local LLM │
                   │  GPT-4     │    │  Claude    │    │  Ollama    │
                   └────────────┘    └────────────┘    └────────────┘
```

## Configuration

### 1. Enable AI Agent in config.toml

```toml
# /etc/firewallx/config.toml

[ai_agent]
enabled = true

# Choose your LLM provider
provider = "openai"  # or "anthropic", "ollama", "custom"

# API Configuration
openai_api_key = "${OPENAI_API_KEY}"  # Use environment variable
# openai_api_key = "sk-..."          # Or hardcode (not recommended)

# Model selection
ai_model = "gpt-4-turbo-preview"  # or "gpt-4", "claude-3-opus-20240229"

# Advanced settings
alert_batch_size = 10          # Process alerts in batches
analysis_interval_secs = 30    # Run analysis every 30 seconds
max_context_alerts = 50        # Keep last N alerts in context
auto_block_enabled = false     # Don't auto-block without confirmation
playbook_output_path = "/var/log/firewallx/playbooks/"
```

### 2. Environment Variables

```bash
# Set API keys securely
export OPENAI_API_KEY="sk-proj-..."
export ANTHROPIC_API_KEY="sk-ant-..."

# Optional: Custom endpoint for self-hosted LLMs
export OLLAMA_BASE_URL="http://localhost:11434"

# Logging verbosity
export RUST_LOG=firewallx::agent=debug
```

## Implementation Details

### Alert Streaming Pipeline

The AI agent receives alerts from IDS via async channel:

```rust
// In firewallx/src/main.rs

// Create alert channel
let (alert_tx, alert_rx) = tokio::sync::mpsc::channel(100);

// Attach to IDS module
engine.ids_mut().alert_tx = Some(alert_tx);

// Spawn AI investigator task
if config.ai_agent_enabled {
    if let Some(key) = &config.openai_api_key {
        let ai_engine = Arc::clone(&shared_engine);
        let model = config.ai_model.clone();
        tokio::spawn(async move {
            agent::spawn_ai_investigator(ai_engine, alert_rx, key, model).await;
        });
    }
}
```

### Alert Message Structure

Each IDS alert is formatted for LLM consumption:

```rust
#[derive(Debug, Clone, Serialize)]
pub struct AiAlert {
    pub timestamp: chrono::DateTime<Utc>,
    pub alert_type: String,      // "port_scan", "brute_force", etc.
    pub severity: String,        // "LOW", "MEDIUM", "HIGH", "CRITICAL"
    pub source_ip: String,
    pub destination_ip: String,
    pub destination_port: Option<u16>,
    pub protocol: String,
    pub description: String,
    pub packet_count: u32,       // Number of packets triggering alert
    pub timeframe_secs: u32,     // Time window of detection
    pub metadata: HashMap<String, String>, // Additional context
}

impl AiAlert {
    /// Format alert for LLM prompt
    pub fn format_for_llm(&self) -> String {
        format!(
            r#"
[ALERT] {} | Severity: {}
Type: {}
Source: {} → Destination: {}:{}
Protocol: {}
Description: {}
Packets: {} over {} seconds
Timestamp: {}
"#,
            self.alert_type,
            self.severity,
            self.source_ip,
            self.destination_ip,
            self.destination_port.unwrap_or(0),
            self.protocol,
            self.description,
            self.packet_count,
            self.timeframe_secs,
            self.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        )
    }
}
```

### AI Investigator Loop

```rust
// In firewallx/src/modules/agent.rs

use reqwest::Client;
use serde_json::json;

pub async fn spawn_ai_investigator(
    engine: SharedEngine,
    mut alert_rx: mpsc::Receiver<AiAlert>,
    api_key: String,
    model: String,
) {
    let client = Client::new();
    let mut alert_buffer = Vec::new();
    
    loop {
        // Collect alerts with timeout
        tokio::select! {
            Some(alert) = alert_rx.recv() => {
                tracing::info!("🤖 AI received IDS alert: {:?}", alert.alert_type);
                alert_buffer.push(alert);
                
                // Process when buffer reaches threshold
                if alert_buffer.len() >= 10 {
                    process_alerts(&client, &api_key, &model, &mut alert_buffer).await;
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                // Timeout: process whatever we have
                if !alert_buffer.is_empty() {
                    process_alerts(&client, &api_key, &model, &mut alert_buffer).await;
                }
            }
        }
    }
}

async fn process_alerts(
    client: &Client,
    api_key: &str,
    model: &str,
    alerts: &mut Vec<AiAlert>,
) {
    // Build prompt with alert context
    let prompt = build_analysis_prompt(alerts);
    
    // Call LLM API
    match call_llm_api(client, api_key, model, &prompt).await {
        Ok(analysis) => {
            tracing::info!("🧠 AI Analysis:\n{}", analysis);
            
            // Parse recommendations
            if let Some(playbook) = parse_playbook_from_analysis(&analysis) {
                save_playbook(&playbook).await;
            }
            
            // Check for immediate action items
            if analysis.contains("IMMEDIATE ACTION REQUIRED") {
                trigger_critical_alert(&analysis);
            }
        }
        Err(e) => {
            tracing::error!("❌ AI analysis failed: {}", e);
        }
    }
    
    // Clear buffer after processing
    alerts.clear();
}
```

### Building the Prompt

Craft effective prompts for security analysis:

```rust
fn build_analysis_prompt(alerts: &[AiAlert]) -> String {
    let mut prompt = String::from(
        r#"You are an expert cybersecurity analyst investigating security alerts from a FirewallX intrusion detection system.

Your tasks:
1. Analyze the provided alerts and identify attack patterns
2. Correlate related events (same source IPs, similar techniques)
3. Assess the severity and potential impact
4. Recommend specific defensive actions
5. Generate FirewallX CLI commands to block identified threats

Format your response as:

## Executive Summary
<Brief overview of the security situation>

## Identified Threats
<List each threat with confidence level: HIGH/MEDIUM/LOW>

## Attack Timeline
<Chronological reconstruction of attacker activities>

## Recommended Actions
<Prioritized list of defensive measures>

## FirewallX Commands
```bash
<Exact commands to implement blocks>
```

## Long-term Recommendations
<Strategic security improvements>

---
ALERT DATA:
"#
    );

    // Append recent alerts (limit to avoid token limits)
    for alert in alerts.iter().rev().take(50) {
        prompt.push_str(&alert.format_for_llm());
    }

    prompt
}
```

### Calling LLM APIs

**OpenAI GPT-4:**

```rust
async fn call_openai(
    client: &Client,
    api_key: &str,
    model: &str,
    prompt: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = client
        .post("https://api.openai.com/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&json!({
            "model": model,
            "messages": [
                {"role": "system", "content": "You are an expert cybersecurity analyst."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,  // Lower temperature for focused analysis
            "max_tokens": 2000,
        }))
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!("OpenAI API error: {}", response.text().await?).into());
    }

    let json: Value = response.json().await?;
    Ok(json["choices"][0]["message"]["content"].as_str().unwrap().to_string())
}
```

**Anthropic Claude:**

```rust
async fn call_anthropic(
    client: &Client,
    api_key: &str,
    model: &str,
    prompt: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2024-01-01")
        .header("Content-Type", "application/json")
        .json(&json!({
            "model": model,
            "max_tokens": 2000,
            "system": "You are an expert cybersecurity analyst.",
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }))
        .send()
        .await?;

    let json: Value = response.json().await?;
    Ok(json["content"][0]["text"].as_str().unwrap().to_string())
}
```

**Self-hosted Ollama:**

```rust
async fn call_ollama(
    client: &Client,
    base_url: &str,
    model: &str,
    prompt: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = client
        .post(format!("{}/api/generate", base_url))
        .header("Content-Type", "application/json")
        .json(&json!({
            "model": model,
            "prompt": prompt,
            "stream": false,
            "options": {
                "temperature": 0.3,
                "num_predict": 2000
            }
        }))
        .send()
        .await?;

    let json: Value = response.json().await?;
    Ok(json["response"].as_str().unwrap().to_string())
}
```

## Example AI Analysis Output

**Input Alerts:**
```
[ALERT] port_scan | Severity: MEDIUM
Source: 203.0.113.50 → Destination: 10.0.0.0/24:1-1024
Packets: 3,456 over 120 seconds

[ALERT] brute_force | Severity: HIGH  
Source: 203.0.113.50 → Destination: 10.0.0.5:22
Packets: 847 over 60 seconds

[ALERT] dpi_match | Severity: CRITICAL
Source: 203.0.113.50 → Destination: 10.0.0.5:80
Pattern: SQL injection attempt detected
```

**AI Analysis Output:**

```markdown
## Executive Summary
Active coordinated attack detected from IP 203.0.113.50 targeting internal network 10.0.0.0/24. Attacker performed reconnaissance via port scanning, followed by SSH brute-force attempts and web application SQL injection attacks. Immediate blocking recommended.

## Identified Threats
1. **Active Intrusion Attempt** - Confidence: HIGH
   - Single source conducting multi-stage attack
   - Escalation from reconnaissance to exploitation
   
2. **SSH Brute Force Attack** - Confidence: HIGH
   - 847 authentication attempts in 60 seconds
   - Targeting critical server at 10.0.0.5
   
3. **SQL Injection Attempt** - Confidence: CRITICAL
   - Payload matching known attack patterns
   - Potential database compromise if successful

## Attack Timeline
- 10:15:00 UTC - Port scan initiated (ports 1-1024)
- 10:17:00 UTC - Scan completed, identified SSH (22) and HTTP (80)
- 10:17:30 UTC - SSH brute force attack began
- 10:18:45 UTC - Switched to SQL injection on web server

## Recommended Actions
1. **IMMEDIATE**: Block source IP 203.0.113.50 at perimeter
2. Enable rate limiting on SSH connections
3. Review web application WAF rules
4. Check database logs for successful injections
5. Implement geo-blocking if source is from high-risk region

## FirewallX Commands
```bash
# Immediate block of attacker
firewallx rule add \
  --name "Block active attacker" \
  --action drop \
  --src_ip "203.0.113.50" \
  --protocol any \
  --direction inbound

# Rate limit SSH to prevent future brute force
firewallx rule add \
  --name "Rate limit SSH" \
  --action allow \
  --port 22 \
  --protocol tcp \
  --direction inbound \
  --max-rate "10/s"

# Add to blocklist for persistence
echo "203.0.113.50" >> /etc/firewallx/blocklist.txt
firewallx blocklist reload
```

## Long-term Recommendations
1. Deploy fail2ban integration for automatic SSH blocking
2. Implement multi-factor authentication for SSH access
3. Add web application firewall (WAF) for SQL injection protection
4. Consider geo-blocking for countries RU, CN if business doesn't require traffic
5. Enable SIEM integration for long-term threat correlation
```

## Automated Playbook Generation

Save AI recommendations as executable playbooks:

```rust
#[derive(Debug, Serialize, Deserialize)]
struct Playbook {
    id: String,
    created_at: DateTime<Utc>,
    triggered_by: Vec<String>,  // Alert IDs
    actions: Vec<PlaybookAction>,
    rollback_commands: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
enum PlaybookAction {
    BlockIp { ip: String, duration_secs: Option<u32> },
    EnableRule { rule_name: String },
    DisableRule { rule_name: String },
    SendNotification { channel: String, message: String },
    ExecuteScript { path: String, args: Vec<String> },
}

async fn save_playbook(playbook: &Playbook) {
    let filename = format!("/var/log/firewallx/playbooks/{}.yaml", playbook.id);
    let yaml = serde_yaml::to_string(playbook).unwrap();
    fs::write(&filename, yaml).await.unwrap();
    
    tracing::info!("📜 Playbook saved: {}", filename);
}
```

## Safety Mechanisms

### 1. Human-in-the-Loop Approval

Require manual approval for critical actions:

```rust
if playbook.actions.iter().any(|a| matches!(a, PlaybookAction::BlockIp { .. })) {
    // Don't execute immediately - wait for approval
    save_playbook(&playbook);
    send_approval_request(&playbook).await;
} else {
    // Safe actions can auto-execute
    execute_playbook(&playbook).await;
}
```

### 2. Rate Limiting AI Actions

Prevent runaway automated responses:

```toml
[ai_agent.safety]
max_blocks_per_hour = 100
require_confirmation_above_severity = "CRITICAL"
cooldown_period_secs = 300  # 5 minutes between major actions
```

### 3. Audit Logging

Log all AI decisions:

```rust
tracing::info!(
    target: "firewallx::audit",
    ai_action = "block_ip",
    target_ip = "203.0.113.50",
    reason = "port_scan + brute_force correlation",
    confidence = "HIGH",
    human_approved = false,
);
```

## Monitoring & Debugging

### View AI Activity

```bash
# Watch live AI analysis
journalctl -u firewallx -f | grep "AI"

# View generated playbooks
ls -lh /var/log/firewallx/playbooks/

# Check API usage
firewallx ai stats

# Output:
# AI Agent Statistics:
# Alerts processed: 1,247
# Analyses performed: 89
# Playbooks generated: 12
# API calls: 89
# Tokens used: ~450K
# Average analysis time: 2.3s
```

### Cost Management

Monitor LLM API costs:

```toml
[ai_agent.budget]
monthly_token_limit = 1_000_000  # Stop if exceeded
alert_at_percentage = 80         # Warn at 80% usage
estimated_cost_per_1k_tokens = 0.03  # For tracking
```
