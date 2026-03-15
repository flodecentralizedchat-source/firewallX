# Generate Firewall Rules from Natural Language

Convert user descriptions of desired network behavior into precise FirewallX CLI commands and configuration rules.

## Purpose

Transform vague security requirements like "block all traffic from Russia" or "only allow web traffic to my server" into production-ready FirewallX rules with proper syntax, priorities, and safety checks.

## Process

### 1. Parse User Intent

Extract key parameters from the request:
- **Action**: Allow, Drop, Reject, Log
- **Direction**: Inbound, Outbound
- **Protocol**: TCP, UDP, ICMP, Any
- **Ports/Services**: Specific ports or well-known services (SSH=22, HTTP=80, etc.)
- **IP Ranges**: CIDR blocks, single IPs, or geo-location references
- **Country Codes**: ISO 3166-1 alpha-2 codes (US, RU, CN, IR, etc.)

### 2. Validate Against Security Best Practices

Check for:
- Overly permissive rules (e.g., "allow all inbound")
- Conflicts with existing rules
- Missing default deny policies
- Potential service disruptions

### 3. Generate CLI Commands

Output formatted FirewallX commands:

```bash
# Example: Block SSH from specific country
firewallx rule add \
  --name "Block SSH from high-risk countries" \
  --action drop \
  --port 22 \
  --protocol tcp \
  --direction inbound \
  --country "RU,CN,KP,IR"
```

### 4. Provide Configuration Snippets

For complex scenarios, generate `config.toml` additions:

```toml
[[rules]]
id = 1
name = "Allow established connections"
action = "allow"
protocol = "tcp"
direction = "inbound"
state = "established"

[[rules]]
id = 2
name = "Block known malicious IPs"
action = "drop"
src_ip = "192.168.100.50"
protocol = "any"
direction = "inbound"
```

## Examples

### Input: "I want to block all incoming traffic from China and Russia except HTTPS"

**Generated Rules:**

```bash
# Rule 1: Allow HTTPS from anywhere (higher priority)
firewallx rule add \
  --priority 10 \
  --name "Allow HTTPS inbound" \
  --action allow \
  --port 443 \
  --protocol tcp \
  --direction inbound

# Rule 2: Block traffic from specified countries (lower priority)
firewallx rule add \
  --priority 20 \
  --name "Block high-risk countries" \
  --action drop \
  --protocol any \
  --direction inbound \
  --country "CN,RU"
```

### Input: "Only allow my application server at 10.0.0.50 to access the database on port 5432"

**Generated Rules:**

```bash
# Allow specific source to destination port
firewallx rule add \
  --name "Allow app server to PostgreSQL" \
  --action allow \
  --src_ip "10.0.0.50" \
  --dst_port 5432 \
  --protocol tcp \
  --direction outbound

# Deny all other database access (implicit in default policy)
```

### Input: "Protect my web server from DDoS attacks"

**Generated Configuration:**

```bash
# Rate limiting configuration
firewallx rule add \
  --name "Rate limit HTTP connections" \
  --action allow \
  --port 80 \
  --protocol tcp \
  --direction inbound

# Enable in config.toml:
# max_connections_per_sec = 100
# Enable IDS for behavioral detection
```

## Output Format

Always provide:
1. ✅ **CLI Commands**: Ready to execute
2. ⚙️ **Config Snippets**: For `config.toml` if needed
3. 📋 **Explanation**: What each rule does
4. ⚠️ **Warnings**: Potential impacts or conflicts
5. 🔍 **Verification**: Commands to test the rules

## Safety Checks

Before generating rules:
- [ ] Confirm user understands the impact of blocking rules
- [ ] Verify no critical services will be disrupted
- [ ] Check for existing conflicting rules
- [ ] Recommend testing in non-production first
- [ ] Suggest logging before enforcing (drop + log)

## Error Handling

If user input is ambiguous:
- Ask clarifying questions about direction, ports, or scope
- Provide examples of common patterns
- Warn about overly broad rules
- Suggest incremental testing approach
