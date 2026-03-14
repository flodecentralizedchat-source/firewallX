#!/bin/bash
# Script to deploy the project to Railway (Backend)
set -e

echo "Deploying backend to Railway..."

# Check if railway CLI is installed
if ! command -v railway &> /dev/null
then
    echo "Railway CLI could not be found. Please install it first:"
    echo "npm i -g @railway/cli"
    exit 1
fi

# Login to Railway if needed
# railway login

# Link or initialize the project
# railway link

echo "Starting deployment..."
railway up

echo "✅ Railway deployment triggered successfully."
echo "Note: FirewallX uses eBPF and requires a privileged container."
echo "Ensure your Railway environment supports required capabilities (CAP_NET_ADMIN, CAP_SYS_ADMIN, CAP_BPF)."
