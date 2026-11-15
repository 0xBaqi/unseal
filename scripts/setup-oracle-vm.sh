#!/usr/bin/env bash
# Unseal — Oracle Cloud Always Free Ubuntu ARM64 Host Setup
set -euo pipefail

echo "=========================================================="
echo " Unseal: Provisioning Oracle Cloud Always Free ARM64 Host"
echo "=========================================================="

# 1. Update OS packages
echo "[1/5] Updating system packages..."
sudo apt-get update -y
sudo apt-get install -y ca-certificates curl gnupg lsb-release git

# 2. Install Docker and Docker Compose
echo "[2/5] Installing Docker Engine & Compose..."
if ! command -v docker &> /dev/null; then
  sudo apt-get install -y docker.io docker-compose-v2
  sudo systemctl enable --now docker
  sudo usermod -aG docker "$USER"
  echo "Docker installed and enabled to start on system boot."
else
  echo "Docker is already installed."
fi

# 3. Clone / Update Unseal Repository
APP_DIR="/opt/unseal"
echo "[3/5] Setting up application directory at ${APP_DIR}..."
if [ ! -d "${APP_DIR}" ]; then
  sudo git clone https://github.com/0xBaqi/unseal.git "${APP_DIR}"
  sudo chown -R "$USER:$USER" "${APP_DIR}"
else
  cd "${APP_DIR}"
  git pull origin main
fi

cd "${APP_DIR}"

# 4. Check for .env.production
echo "[4/5] Checking environment configuration..."
if [ ! -f .env.production ]; then
  cp .env.production.example .env.production
  chmod 600 .env.production
  echo ""
  echo "⚠️  Action required: Please edit ${APP_DIR}/.env.production with real production secrets:"
  echo "    - R2_ACCOUNT_ID"
  echo "    - R2_ACCESS_KEY_ID"
  echo "    - R2_SECRET_ACCESS_KEY"
  echo "    - TUNNEL_TOKEN"
  echo ""
else
  echo "Configuration .env.production found."
fi

# 5. Instructions for startup
echo "[5/5] Setup completed!"
echo "To start Unseal with automatic restart on VM reboot, run:"
echo "    cd ${APP_DIR} && docker compose up -d --build"
echo "To view live logs:"
echo "    cd ${APP_DIR} && docker compose logs -f"
echo "=========================================================="
