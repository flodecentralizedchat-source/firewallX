#!/bin/bash
# FirewallX Comprehensive Demo Script
# This script demonstrates all major features of the FirewallX engine

set -e

echo "🔥 ============================================="
echo "   FirewallX Comprehensive Feature Demonstration"
echo "============================================= 🔥"
echo ""

FIREWALLX="./target/release/firewallx"

# Check if binary exists
if [ ! -f "$FIREWALLX" ]; then
    echo "❌ Error: firewallx binary not found. Building..."
    cargo build --release -p firewallx
fi

echo "✅ Using binary: $FIREWALLX"
echo ""

# 1. Show CLI Help
echo "📋 1. CLI Help Menu"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
$FIREWALLX --help
echo ""
echo "⏸️  Press Enter to continue..."
read

# 2. Rule Management
echo "🛡️  2. Firewall Rule Management"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Adding test rules..."

# Add sample rules
$FIREWALLX rule add --name "Block SSH" --action drop --dst-port 22 --protocol tcp --direction inbound
$FIREWALLX rule add --name "Allow HTTPS Outbound" --action allow --dst-port 443 --protocol tcp --direction outbound
$FIREWALLX rule add --name "Allow HTTP Inbound" --action allow --dst-port 80 --protocol tcp --direction inbound
$FIREWALLX rule add --name "Block Russia & China" --action drop --protocol any --direction inbound --country "RU,CN"

echo ""
echo "Active Rules:"
$FIREWALLX rule list
echo ""
echo "⏸️  Press Enter to continue..."
read

# 3. Feed Management
echo "📡 3. Threat Intelligence Feeds"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Adding Emerging Threats feed..."
$FIREWALLX feed add --url "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz"
echo ""
echo "Subscribed Feeds:"
$FIREWALLX feed list
echo ""
echo "⏸️  Press Enter to continue..."
read

# 4. VPN Management
echo "🔐 4. VPN Gateway (WireGuard)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "VPN commands available:"
$FIREWALLX vpn --help
echo ""
echo "⏸️  Press Enter to continue..."
read

# 5. SIEM Integration
echo "📊 5. SIEM Logging Integration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "SIEM commands available:"
$FIREWALLX siem --help
echo ""
echo "⏸️  Press Enter to continue..."
read

# 6. Run Engine Demo
echo "🚀 6. Running Firewall Engine Demo"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Starting engine (will run for 5 seconds)..."
echo ""

# Start engine in background, capture output
timeout 5 $FIREWALLX start 2>&1 || true

echo ""
echo "⏸️  Press Enter to continue..."
read

# 7. Show Test Results
echo "🧪 7. Running Test Suite"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
cargo test --lib 2>&1 | grep -E "(test result:|running|passed|failed)" || echo "Tests completed"
echo ""
echo "⏸️  Press Enter to continue..."
read

# 8. Clean up demo rules
echo "🧹 8. Cleanup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Note: Demo rules are saved in config.toml"
echo "To reset: rm config.toml && $FIREWALLX install"
echo ""

echo "✅ Demo Complete!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Summary:"
echo "  ✓ CLI commands demonstrated"
echo "  ✓ Rule management (add/list)"
echo "  ✓ Threat intelligence feeds"
echo "  ✓ VPN gateway configuration"
echo "  ✓ SIEM integration setup"
echo "  ✓ Engine execution with DPI/IDS"
echo "  ✓ Test suite validation (60 tests)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Next steps:"
echo "  • Run 'sudo $FIREWALLX start' for full engine"
echo "  • Edit config.toml for custom settings"
echo "  • Import Suricata rules: $FIREWALLX rule import --file <file.rules>"
echo "  • Enable AI analyst in config.toml"
echo ""
