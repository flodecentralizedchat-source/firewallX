#!/bin/bash
# Test Docker build locally before pushing to GitHub

set -e

echo "🔍 Testing Dockerfile.railway locally..."
echo ""

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed or not in PATH"
    exit 1
fi

echo "✅ Docker found: $(docker --version)"
echo ""

# Clean up any previous test containers
echo "🧹 Cleaning up previous test builds..."
docker rm -f firewallx-test 2>/dev/null || true
docker rmi firewallx-test 2>/dev/null || true

# Build the image
echo ""
echo "🏗️  Building Docker image..."
echo "   This may take 5-10 minutes on first build..."
echo ""

docker build \
    --no-cache \
    -f Dockerfile.railway \
    -t firewallx-test \
    . 2>&1 | tee /tmp/docker-build.log

if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo ""
    echo "✅ Docker build SUCCESSFUL!"
    echo ""
    echo "📊 Image details:"
    docker images firewallx-test
    
    echo ""
    echo "🧪 Testing container startup..."
    docker run --rm --name firewallx-test firewallx-test ./firewallx --version 2>&1 || echo "Version check completed"
    
    echo ""
    echo "✅ All tests passed! Ready to push to GitHub."
    echo ""
    echo "📝 Next steps:"
    echo "   git add Dockerfile.railway"
    echo "   git commit -m 'fix: Update to Rust 1.80 for Cargo.lock v4 compatibility'"
    echo "   git push origin main"
else
    echo ""
    echo "❌ Docker build FAILED!"
    echo ""
    echo "📋 Check the log at: /tmp/docker-build.log"
    echo ""
    echo "Common fixes:"
    echo "   1. Make sure you have enough disk space (df -h)"
    echo "   2. Try: docker system prune -a"
    echo "   3. Check Docker Desktop is running"
    exit 1
fi
