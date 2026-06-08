# ── Build stage ────────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /sift-orchestrator ./cmd/orchestrator

# ── Runtime stage ───────────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache \
    ca-certificates \
    nmap \
    && adduser -D -u 1000 sift

# Install Nuclei
RUN wget -qO /tmp/nuclei.tar.gz \
    https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.2.9_linux_amd64.zip \
    || true

# Install naabu (port scanner)
RUN wget -qO /tmp/naabu.tar.gz \
    https://github.com/projectdiscovery/naabu/releases/latest/download/naabu_2.3.1_linux_amd64.zip \
    || true

COPY --from=builder /sift-orchestrator /usr/local/bin/sift-orchestrator

USER sift
WORKDIR /home/sift

ENTRYPOINT ["/usr/local/bin/sift-orchestrator"]
