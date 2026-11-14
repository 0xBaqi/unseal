#!/bin/bash
set -e

echo "[unseal-runner] Initializing Unseal production container..."

# Run migrations/seed checks
mkdir -p data

# Start Node.js server
node src/server.js &
NODE_PID=$!
echo "[unseal-runner] Node.js server started (PID: $NODE_PID) on port ${PORT:-3000}"

# If TUNNEL_TOKEN is configured, run cloudflared to maintain unseal.baronal.xyz
if [ -n "$TUNNEL_TOKEN" ]; then
  echo "[unseal-runner] Starting Cloudflare Tunnel connector with TUNNEL_TOKEN..."
  cloudflared tunnel run --token "$TUNNEL_TOKEN" &
  CF_PID=$!
  echo "[unseal-runner] Cloudflare Tunnel connector started (PID: $CF_PID)"
fi

# Wait for background processes
wait -n
