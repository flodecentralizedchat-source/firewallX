#!/bin/bash
# Script to deploy the frontend to Vercel
set -e

echo "Deploying frontend to Vercel..."

# Check if vercel CLI is installed
if ! command -v vercel &> /dev/null
then
    echo "Vercel CLI could not be found. Please install it first:"
    echo "npm i -g vercel"
    exit 1
fi

# If you have a specific frontend directory, cd into it
# cd frontend

echo "Starting deployment..."
vercel --prod

echo "✅ Vercel deployment triggered successfully."
