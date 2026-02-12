#!/bin/bash

# Setup script for ngrok tunnel
# This script sets up ngrok to expose the NisHack agent API to the internet

echo "=== NisHack ngrok Setup ==="
echo ""

# Check if ngrok is installed
if ! command -v ngrok &> /dev/null; then
    echo "❌ ngrok is not installed"
    echo ""
    echo "Please install ngrok:"
    echo "1. Download from: https://ngrok.com/download"
    echo "2. Or install via Homebrew: brew install ngrok/ngrok/ngrok"
    echo "3. Or install manually:"
    echo "   curl -sLO https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-darwin-arm64.zip"
    echo "   unzip ngrok-v3-stable-darwin-arm64.zip"
    echo "   sudo mv ngrok /usr/local/bin/"
    echo ""
    exit 1
fi

echo "✅ ngrok is installed: $(ngrok version)"
echo ""

# Check if ngrok is authenticated
if ! ngrok config check &> /dev/null; then
    echo "⚠️  ngrok is not authenticated"
    echo ""
    echo "To authenticate:"
    echo "1. Sign up at https://dashboard.ngrok.com/signup"
    echo "2. Get your authtoken from https://dashboard.ngrok.com/get-started/your-authtoken"
    echo "3. Run: ngrok config add-authtoken <your_token>"
    echo ""
    echo "Continuing without authentication (limited features)..."
    echo ""
fi

# Default port
PORT=${1:-7770}

echo "🚀 Starting ngrok tunnel on port $PORT..."
echo ""
echo "Available endpoints:"
echo "  - /health       - Check agent status"
echo "  - /info         - System information"
echo "  - /violations   - Violation history"
echo "  - /config       - Current configuration"
echo "  - /screenshot   - Latest screenshot (base64)"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Start ngrok
ngrok http $PORT
