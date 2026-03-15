#!/bin/bash
# Deploy FirewallX Backend to Railway
set -e

echo "💚 Deploying FirewallX Backend to Railway..."

# Check if railway CLI is installed
if ! command -v railway &> /dev/null; then
    echo "❌ Railway CLI not found. Installing..."
    npm install -g @railway/cli
fi

# Login if needed
if [ ! -f ~/.config/railway/token ]; then
    echo "🔐 Please login to Railway..."
    railway login
fi

# Initialize or link project
if [ ! -f .railway/project.json ]; then
    echo "📋 Initializing Railway project..."
    railway init || railway link
fi

# Set environment variables
echo "⚙️  Configuring environment..."
railway variables set \
    RUST_LOG=info \
    PROMETHEUS_ENABLED=true \
    PROMETHEUS_PORT=9100 \
    AI_AGENT_ENABLED=false \
    CONFIG_PATH=/app/config.toml

echo "🚀 Starting deployment..."
railway up

echo ""
echo "✅ Railway deployment complete!"
echo ""
echo "💡 Next steps:"
echo "  1. Get your Railway URL from dashboard"
echo "  2. Update VITE_API_URL in Vercel: vercel env set VITE_API_URL https://your-app.railway.app production"
echo "  3. Redeploy Vercel frontend if needed"
echo ""
echo "⚠️  Note: FirewallX runs in userspace mode on Railway (no eBPF support)"
echo "   This provides full firewall functionality via the REST API"
