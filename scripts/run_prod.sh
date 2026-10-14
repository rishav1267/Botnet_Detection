#!/usr/bin/env bash
# NETGUARD IoT Botnet Detection System — Production Server Launcher
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
cd "$DIR"

echo "========================================================"
echo " Starting NETGUARD IoT Backend [PRODUCTION MODE]"
echo " Directory: $DIR"
echo "========================================================"

export NODE_ENV=production
export PORT="${PORT:-8080}"

python3 backend/app.py "$PORT"
