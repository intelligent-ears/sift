#!/usr/bin/env bash
set -euo pipefail

# ── Sift local dev startup script ──────────────────────────────────────────────

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[sift]${NC} $1"; }
warn()  { echo -e "${YELLOW}[warn]${NC} $1"; }
error() { echo -e "${RED}[error]${NC} $1"; exit 1; }

# Check prerequisites
command -v docker   >/dev/null 2>&1 || error "docker not found"
command -v go       >/dev/null 2>&1 || error "go not found"

info "Starting Sift infrastructure..."
docker compose up -d nats redis postgres

info "Waiting for infrastructure to be healthy..."
sleep 5

# Check if nuclei is installed
if ! command -v nuclei >/dev/null 2>&1; then
    warn "nuclei not found — installing..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
fi

# Update nuclei templates
info "Updating Nuclei templates..."
nuclei -update-templates -silent || warn "Could not update Nuclei templates — using existing"

# Start ML middleware (optional)
if [[ "${SIFT_ML:-true}" == "true" ]]; then
    info "Starting ML triage middleware..."
    docker compose up -d ml-triage
else
    warn "ML middleware disabled (SIFT_ML=false)"
fi

# Build the orchestrator
info "Building orchestrator..."
go build -o /tmp/sift-orchestrator ./cmd/orchestrator

# Build the CLI
info "Building CLI..."
go build -o /tmp/sift ./cmd/sift

info "Running database migrations..."
POSTGRES_DSN="postgres://sift:sift@localhost:5432/sift?sslmode=disable" \
    /tmp/sift migrate 2>/dev/null || warn "Migrations may have already run"

info "Starting orchestrator..."
NATS_URL="nats://localhost:4222" \
POSTGRES_DSN="postgres://sift:sift@localhost:5432/sift?sslmode=disable" \
REDIS_ADDR="localhost:6379" \
SIFT_ML_ENDPOINT="localhost:50051" \
NUCLEI_TEMPLATES_PATH="${HOME}/.nuclei-templates" \
NUCLEI_MAX_TEMPLATES="50" \
SCANNING_PACKETS_PER_SECOND="5" \
    /tmp/sift-orchestrator &

ORCH_PID=$!
echo $ORCH_PID > /tmp/sift-orchestrator.pid

info "Orchestrator started (PID: $ORCH_PID)"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Sift is running"
echo ""
echo "  Scan a target:"
echo "    /tmp/sift scan --target example.com"
echo ""
echo "  Bulk scan:"
echo "    /tmp/sift scan --file targets.txt"
echo ""
echo "  View findings:"
echo "    /tmp/sift findings --target example.com"
echo ""
echo "  Stop:"
echo "    ./scripts/stop.sh"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
