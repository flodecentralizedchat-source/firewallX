# FirewallX .qoder Directory - Complete Reference

This directory contains **fully functional AI agents and skills** designed specifically for the FirewallX project. These files empower your AI assistant to provide expert-level assistance across all aspects of FirewallX development, deployment, and operations.

## 📁 Directory Structure

```
.qoder/
├── agents/          # Specialized AI personas with deep expertise
│   ├── firewallx-security-agent.md    → Security analysis & threat detection
│   ├── ebpf-dev-agent.md              → eBPF kernel programming expert
│   └── deployment-agent.md            → Cloud deployment & DevOps automation
└── skills/          # Step-by-step procedural guides
    ├── generate-firewall-rules.md     → Natural language → CLI commands
    ├── analyze-traffic-patterns.md    → Network telemetry analysis
    ├── configure-ebpf-performance.md  → eBPF optimization techniques
    ├── deploy-to-cloud.md             → Multi-cloud deployment guides
    ├── import-suricata-rules.md       → IDS signature conversion
    ├── setup-ai-analyst.md            → LLM integration for threat analysis
    └── troubleshoot-connectivity.md   → Systematic debugging framework
```

---

## 🤖 Agents (3 Specialized Personas)

### 1. **FirewallX Security Agent** 
*File: `agents/firewallx-security-agent.md`*

**Expertise:**
- Stateful firewall engines and rule evaluation
- Deep Packet Inspection (DPI) signatures  
- Intrusion Detection/Prevention Systems (IDS/IPS)
- Threat intelligence and blocklist management
- VPN gateway configurations (WireGuard, IPSec)

**Use when you need to:**
- Analyze firewall rules for security gaps
- Generate country-based blocking policies
- Convert Suricata/Snort signatures to FirewallX format
- Review IDS alerts and correlate attack patterns
- Audit configurations for best practices

**Example queries:**
```
"Analyze my current firewall rules and suggest improvements"
"Generate blocking rules for these malicious IPs from my SIEM logs"
"Review this Suricata rules file and convert to FirewallX format"
```

---

### 2. **FirewallX eBPF Development Agent**
*File: `agents/ebpf-dev-agent.md`*

**Expertise:**
- Writing eBPF programs in Rust/C with Aya framework
- XDP (Express Data Path) hooks for line-rate filtering
- eBPF maps (HashMaps, RingBuffers, PerCpuArray)
- Linux kernel networking and packet flow
- Performance optimization for minimal overhead

**Use when you need to:**
- Write new XDP programs for custom packet inspection
- Debug eBPF verifier errors
- Optimize HashMap lookups for faster IP blocking
- Implement ring buffers for event streaming
- Chain multiple eBPF programs with tail calls

**Example queries:**
```
"Write an XDP program that drops packets from a HashMap blocklist"
"My eBPF program fails verification - help me fix it"
"Implement a ring buffer for streaming packet events to userspace"
```

---

### 3. **FirewallX Deployment Agent**
*File: `agents/deployment-agent.md`*

**Expertise:**
- Container orchestration (Docker, Kubernetes, Railway, Vercel)
- Infrastructure as Code (Terraform, Ansible)
- CI/CD pipelines for security tooling
- Monitoring integration (Prometheus, Grafana, SIEM)
- High-availability deployments across cloud providers

**Use when you need to:**
- Deploy FirewallX to AWS/GCP/Azure with one command
- Create Kubernetes manifests with proper RBAC
- Configure Prometheus metrics and Grafana dashboards
- Design active-passive failover clusters
- Set up automated backups and disaster recovery

**Example queries:**
```
"Deploy FirewallX to my Kubernetes cluster with Helm"
"Create a Docker Compose file for testing eBPF drops"
"Configure Prometheus scraping for FirewallX metrics"
```

---

## 🛠️ Skills (7 Procedural Guides)

### Skill 1: **Generate Firewall Rules from Natural Language**
*File: `skills/generate-firewall-rules.md`*

**What it does:** Converts vague security requirements into precise FirewallX CLI commands.

**Input example:** "I want to block all incoming traffic from China and Russia except HTTPS"

**Output includes:**
- ✅ Ready-to-execute CLI commands with proper priorities
- ⚙️ `config.toml` configuration snippets
- 📋 Explanations of what each rule does
- ⚠️ Warnings about potential impacts
- 🔍 Verification commands to test the rules

**Safety features:**
- Validates against overly permissive rules
- Checks for conflicts with existing rules
- Recommends testing in non-production first

---

### Skill 2: **Analyze Network Traffic Patterns**
*File: `skills/analyze-traffic-patterns.md`*

**What it does:** Transforms raw firewall logs into actionable threat intelligence.

**Analyzes:**
- Port scans and reconnaissance activity
- Brute-force login attempts
- DDoS and flood attacks
- Data exfiltration patterns
- Malware C2 communication

**Output formats:**
- Executive summary with threat overview
- Detailed incident reports with timelines
- Recommended defensive actions with CLI commands
- Integration with SIEM for long-term correlation

**Example analysis:**
```
📊 Security Report (Last 24 Hours)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Packets Analyzed: 1,234,567
Allowed: 98.2% | Dropped: 1.8%
Threats Detected: 47
  - Port Scans: 12
  - Brute Force: 8
  - DPI Blocked: 23
  
Top Attackers:
  1. 203.0.113.50 (Russia) - 234 drops
  2. 198.51.100.25 (China) - 189 drops
```

---

### Skill 3: **Configure eBPF Performance Optimization**
*File: `skills/configure-ebpf-performance.md`*

**What it does:** Tunes eBPF programs for maximum throughput and minimal latency.

**Coverage:**
- XDP attachment modes (Native vs Generic vs Offload)
- Map size optimization (blocklist HashMaps, ring buffers)
- Per-CPU maps for multi-core scaling
- Tail calls for modular processing
- Performance benchmarks and troubleshooting

**Performance targets:**
| Hardware | Max PPS | Latency (p99) |
|----------|---------|---------------|
| AWS c6i.xlarge | 10M | 2.5μs |
| Bare-metal i9-13900K | 20M | 1.2μs |
| Cloud m6i.metal | 50M | 0.8μs |

**Key optimizations:**
- LRU caches for hot blocklist entries
- Bloom filters for space efficiency
- Jiffies-based time checks without syscalls

---

### Skill 4: **Deploy to Cloud Platforms**
*File: `skills/deploy-to-cloud.md`*

**What it does:** One-command deployments to major cloud providers and container platforms.

**Supported platforms:**
- ✅ AWS EC2 (with full bash deployment script)
- ✅ Google Cloud (Terraform configuration)
- ✅ Microsoft Azure (ARM templates)
- ✅ Railway.app (native deployment)
- ✅ Vercel (API-only mode)
- ✅ Kubernetes (Helm chart + DaemonSet)

**Includes:**
- Complete deployment scripts with IAM/RBAC
- Security hardening guidelines
- Monitoring integration (Prometheus exporters)
- High-availability configurations
- Rollback procedures

**Example (AWS):**
```bash
./deploy-aws.sh
# → Launches c6i.xlarge instance
# → Installs FirewallX via .deb package
# → Configures default deny policy
# → Attaches eBPF to network interface
# → Returns public IP and SSH instructions
```

---

### Skill 5: **Import and Convert Suricata Rules**
*File: `skills/import-suricata-rules.md`*

**What it does:** Automatically converts Suricata/Snort signatures to FirewallX DPI rules.

**Supports:**
- Suricata format (`.rules` files)
- Snort format (`.sid` files)
- Emerging Threats feed
- Custom regex patterns (PCRE)

**Conversion process:**
1. Parse rule structure (action, protocol, ports, options)
2. Map content matches to FirewallX DPI engine
3. Convert PCRE regex to Rust regex
4. Generate `config.toml` or JSON output
5. Validate syntax and test against sample payloads

**Features:**
- HTTP field mapping (method, URI, headers, body)
- Byte extraction and pattern matching
- Flow characteristics (established, direction)
- Classification metadata (classtype, references)

**Usage:**
```bash
firewallx rule import --file emerging-threats.rules
# Output: Successfully imported 1,247 signatures
```

---

### Skill 6: **Setup AI Security Analyst Integration**
*File: `skills/setup-ai-analyst.md`*

**What it does:** Streams IDS alerts to LLM APIs (GPT-4, Claude, etc.) for autonomous threat analysis.

**Architecture:**
```
FirewallX IDS → Alert Queue → AI Investigator → LLM API → Playbook Generation
```

**Configuration:**
```toml
[ai_agent]
enabled = true
provider = "openai"
ai_model = "gpt-4-turbo-preview"
alert_batch_size = 10
analysis_interval_secs = 30
```

**Capabilities:**
- Correlates related alerts (same source IP, similar techniques)
- Reconstructs attack timelines
- Generates defensive recommendations
- Produces ready-to-execute FirewallX commands
- Creates automated playbooks with human approval workflow

**Example output:**
```markdown
## Executive Summary
Active coordinated attack detected from IP 203.0.113.50...

## FirewallX Commands
```bash
firewallx rule add \
  --name "Block active attacker" \
  --action drop \
  --src_ip "203.0.113.50" \
  --protocol any \
  --direction inbound
```
```

**Safety mechanisms:**
- Human-in-the-loop approval for critical actions
- Rate limiting on automated responses
- Comprehensive audit logging
- Budget controls for API costs

---

### Skill 7: **Troubleshoot Firewall Connectivity Issues**
*File: `skills/troubleshoot-connectivity.md`*

**What it does:** Systematic diagnostic framework for resolving FirewallX issues.

**Covers 6 major issue categories:**
1. False positives (legitimate traffic blocked)
2. False negatives (malicious traffic not blocked)
3. eBPF program load failures
4. High CPU/memory usage
5. VPN tunnel connectivity problems
6. SIEM integration failures

**Diagnostic approach:**
```bash
# Step 1: Gather information
systemctl status firewallx
journalctl -u firewallx --since "10 minutes ago"
firewallx rule list
bpftool prog list | grep firewallx

# Step 2: Identify symptom category
# Step 3: Follow targeted troubleshooting tree
# Step 4: Apply resolution and verify
```

**Advanced techniques:**
- Packet capture analysis with tcpdump/Wireshark
- Rule chain visualization
- Performance profiling with perf/flamegraph
- Core dump analysis with gdb
- Emergency access recovery procedures

---

## 🎯 How to Use These Files

### For Users

When you need help with FirewallX, simply ask questions related to these domains. The AI will automatically adopt the appropriate persona and follow the relevant skill guide.

**Examples:**
- "Help me deploy FirewallX to AWS" → Triggers **Deployment Agent** + **Deploy to Cloud** skill
- "Why is my SSH connection being blocked?" → Triggers **Security Agent** + **Troubleshoot** skill
- "Convert these Suricata rules to FirewallX format" → Triggers **Security Agent** + **Import Rules** skill
- "My eBPF program won't load" → Triggers **eBPF Agent** + **Troubleshoot** skill

### For Developers

These files serve as comprehensive documentation for:
- Understanding FirewallX architecture
- Learning eBPF best practices
- Implementing new features
- Writing test cases
- Creating deployment automation

---

## 🔧 Technical Details

### File Format

All files use Markdown with structured sections:
- **Purpose**: What this skill/agent does
- **Capabilities**: Specific competencies
- **Process**: Step-by-step procedures
- **Examples**: Real-world usage scenarios
- **Safety**: Risk mitigation guidelines
- **Tools**: Available commands and utilities

### Integration Points

These files align with FirewallX modules:
- `firewallx/src/modules/engine.rs` → Rule evaluation
- `firewallx/src/modules/dpi.rs` → Payload inspection
- `firewallx/src/modules/ids.rs` → Behavioral detection
- `firewallx/src/modules/vpn.rs` → Tunnel management
- `firewallx-ebpf/src/main.rs` → XDP programs
- `firewallx/src/config.rs` → Configuration management

---

## 📊 Coverage Matrix

| Topic | Agent | Skill | Depth |
|-------|-------|-------|-------|
| Rule generation | ✅ Security | ✅ Generate | CLI + Config |
| Traffic analysis | ✅ Security | ✅ Analyze | Telemetry + SIEM |
| eBPF programming | ✅ eBPF Dev | ✅ Configure | XDP + Maps |
| Cloud deployment | ✅ Deployment | ✅ Deploy | AWS/GCP/Azure/K8s |
| Signature import | ✅ Security | ✅ Import | Suricata/Snort |
| AI integration | ✅ Security | ✅ Setup AI | GPT-4/Claude/Ollama |
| Troubleshooting | ✅ All | ✅ Troubleshoot | Full stack |

---

## 🚀 Next Steps

1. **Test the agents**: Ask questions to trigger different personas
2. **Extend the skills**: Add new procedures as you discover use cases
3. **Share feedback**: Improve these files based on real-world usage
4. **Contribute examples**: Add real deployment scenarios and success stories

---

## 📝 License

These agent and skill files are part of the FirewallX project and available under the MIT License.

---

**Created for:** FirewallX Project  
**Version:** 0.2.0  
**Date:** March 15, 2026  
**Total files:** 10 (3 agents + 7 skills)  
**Total lines:** ~3,500 lines of expert guidance
