#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
NC='\033[0m'
info() { echo -e "${GREEN}[sift]${NC} $1"; }

info "Stopping orchestrator..."
if [ -f /tmp/sift-orchestrator.pid ]; then
    kill "$(cat /tmp/sift-orchestrator.pid)" 2>/dev/null || true
    rm /tmp/sift-orchestrator.pid
fi

info "Stopping infrastructure..."
docker compose down

info "Done."
