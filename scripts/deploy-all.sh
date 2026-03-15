#!/bin/bash
# Complete deployment script for FirewallX to Vercel + Railway
# This script automates the entire deployment process

set -e

echo "🔥 ============================================="
echo "   FirewallX Automated Deployment"
echo "   Deploying to Vercel (Frontend) + Railway (Backend)"
echo "============================================= 🔥"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_step() {
    echo -e "${BLUE}▶ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Check prerequisites
print_step "Checking prerequisites..."

# Check Node.js
if ! command -v node &> /dev/null; then
    print_error "Node.js is not installed. Please install Node.js 18+ first."
    exit 1
fi
print_success "Node.js found: $(node --version)"

# Check npm
if ! command -v npm &> /dev/null; then
    print_error "npm is not installed."
    exit 1
fi

# Check Vercel CLI
if ! command -v vercel &> /dev/null; then
    print_warning "Vercel CLI not found. Installing..."
    npm install -g vercel
    print_success "Vercel CLI installed"
else
    print_success "Vercel CLI found: $(vercel --version)"
fi

# Check Railway CLI
if ! command -v railway &> /dev/null; then
    print_warning "Railway CLI not found. Installing..."
    npm install -g @railway/cli
    print_success "Railway CLI installed"
else
    print_success "Railway CLI found"
fi

echo ""
print_step "Building Frontend..."

# Build UI
cd firewallx-ui
npm install
npm run build
cd ..
print_success "Frontend built successfully"

echo ""
print_step "Deploying Frontend to Vercel..."

# Check if already logged in to Vercel
if [ ! -f ~/.vercel/auth.json ]; then
    print_warning "Not logged in to Vercel. Please login..."
    vercel login
fi

# Deploy to Vercel
VERCEL_DEPLOY_OUTPUT=$(vercel --prod)
echo "$VERCEL_DEPLOY_OUTPUT"

# Extract deployment URL
VERCEL_URL=$(echo "$VERCEL_DEPLOY_OUTPUT" | grep -oP 'https://[a-zA-Z0-9-]+\.vercel\.app' | head -1)

if [ -z "$VERCEL_URL" ]; then
    print_error "Failed to extract Vercel deployment URL"
    exit 1
fi

print_success "Frontend deployed to: $VERCEL_URL"

echo ""
print_step "Deploying Backend to Railway..."

# Check if already logged in to Railway
if [ ! -f ~/.config/railway/token ]; then
    print_warning "Not logged in to Railway. Please login..."
    railway login
fi

# Initialize or link project
if [ ! -f .railway/project.json ]; then
    print_warning "Project not linked to Railway. Initializing..."
    railway init || railway link
fi

# Set environment variables
print_step "Configuring Railway environment..."
railway variables set \
    RUST_LOG=info \
    PROMETHEUS_ENABLED=true \
    PROMETHEUS_PORT=9100 \
    AI_AGENT_ENABLED=false \
    CONFIG_PATH=/app/config.toml

print_success "Environment variables configured"

# Deploy to Railway
print_step "Building and deploying to Railway..."
railway up

# Get Railway URL
RAILWAY_URL=$(railway domain list 2>/dev/null | grep -oP 'https://[a-zA-Z0-9.-]+\.railway\.app' | head -1 || echo "")

if [ -z "$RAILWAY_URL" ]; then
    print_warning "Could not automatically extract Railway URL. Check your Railway dashboard."
    RAILWAY_URL="your-railway-app.railway.app"
fi

print_success "Backend deployed to: $RAILWAY_URL"

echo ""
print_step "Updating frontend with backend URL..."

# Update Vercel environment variable
vercel env set VITE_API_URL https://$RAILWAY_URL production

print_success "Frontend configured with backend URL"

echo ""
echo "=============================================="
echo "   🎉 Deployment Complete!"
echo "=============================================="
echo ""
echo "Frontend (Vercel):"
echo "  🌐 URL: $VERCEL_URL"
echo "  📊 Dashboard: https://vercel.com/dashboard"
echo ""
echo "Backend (Railway):"
echo "  🌐 URL: https://$RAILWAY_URL"
echo "  💚 Dashboard: https://railway.app/dashboard"
echo "  📈 Metrics: https://$RAILWAY_URL:9100/metrics"
echo "  ❤️  Health: https://$RAILWAY_URL/health"
echo ""
echo "Next Steps:"
echo "  1. Visit $VERCEL_URL to see your dashboard"
echo "  2. Test API endpoints at https://$RAILWAY_URL/api"
echo "  3. Configure firewall rules via the UI or CLI"
echo "  4. Monitor metrics at https://$RAILWAY_URL:9100/metrics"
echo ""
echo "Useful Commands:"
echo "  • View Vercel logs: vercel logs $VERCEL_URL"
echo "  • View Railway logs: railway logs --follow"
echo "  • Add firewall rule: curl -X POST https://$RAILWAY_URL/api/rules ..."
echo "  • Redeploy: ./scripts/deploy-all.sh"
echo ""
echo "Documentation:"
echo "  📖 See DEPLOYMENT_GUIDE.md for detailed instructions"
echo "  📖 See ARCHITECTURE.md for technical details"
echo ""
print_success "All done! Your FirewallX is now protecting networks from the cloud! 🚀"
echo ""
