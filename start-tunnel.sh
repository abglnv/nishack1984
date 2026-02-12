#!/bin/bash

# Quick setup for NisHack with ngrok
# This exposes the agent API to the internet for teacher's dashboard access

echo "🚀 Starting NisHack Agent with ngrok tunnel..."
echo ""

# Check if nishack is running
if pgrep -f "nishack" > /dev/null; then
    echo "✅ NisHack agent is already running"
else
    echo "⚠️  NisHack agent is not running"
    echo "Starting agent..."
    cd /Users/bebdyshev/Documents/Github/nishack1984
    cargo run &
    sleep 3
fi

echo ""
echo "📡 Creating ngrok tunnel on port 7770..."
echo ""
echo "Available API endpoints:"
echo "  GET /health       - Agent status and uptime"
echo "  GET /info         - System information (CPU, RAM, OS)"
echo "  GET /violations   - Recent violations list"
echo "  GET /config       - Ban lists configuration"
echo "  GET /screenshot   - Latest screenshot (base64 JPEG)"
echo ""
echo "🔗 Teacher's dashboard will access via the ngrok URL"
echo ""

ngrok http 7770
