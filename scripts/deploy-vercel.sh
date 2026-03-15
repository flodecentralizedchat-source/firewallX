#!/bin/bash
# Deploy FirewallX Frontend to Vercel
set -e

echo "🎨 Deploying FirewallX Frontend to Vercel..."

# Check if vercel CLI is installed
if ! command -v vercel &> /dev/null; then
    echo "❌ Vercel CLI not found. Installing..."
    npm install -g vercel
fi

# Build the UI first
echo "📦 Building UI..."
cd firewallx-ui
npm install
npm run build
cd ..
echo "✅ UI built successfully"

# Login if needed
if [ ! -f ~/.vercel/auth.json ]; then
    echo "🔐 Please login to Vercel..."
    vercel login
fi

# Deploy
echo "🚀 Starting deployment..."
vercel --prod

echo ""
echo "✅ Vercel deployment complete!"
echo "💡 Next step: Deploy backend to Railway using ./scripts/deploy-railway.sh"
echo "💡 Then update VITE_API_URL environment variable in Vercel dashboard"
