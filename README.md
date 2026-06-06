# Sift

**Sift** is a modular, large-scale vulnerability scanner built in Go. It is designed for national CERTs, security researchers, and bug bounty hunters who need to scan thousands of targets reliably, with signal — not noise.

Sift's core thesis: most scanners either run everything (slow, noisy) or nothing (fast, blind). Sift fingerprints targets first, then selects only the relevant checks using a two-stage metadata filter and online ML re-ranker — making comprehensive scanning feasible at scale.

---

## What makes Sift different

**Context-aware Nuclei orchestration**
Sift fingerprints every target before scanning. The smart Nuclei router filters 10,000+ templates down to the relevant 50 using tag matching, technology detection, and version range applicability. A ML re-ranker then scores candidates using per-template Bayesian hit-rate tracking, updated online after every scan. No blind template runs. No wasted compute.

**Online ML triage middleware**
A Python/gRPC microservice reduces false positives, re-ranks findings by severity in target context, and clusters similar findings across scans. It adapts to new deployments within the first few hundred scans — no retraining required. If the ML service is unavailable, scanning continues unaffected.

**GraphQL attack surface coverage**
A dedicated native module covers GraphQL vulnerabilities not addressed by standard template libraries: introspection exposure, query depth and complexity abuse, batching attacks, auth bypass on sensitive resolvers, injection via variables, and alias-based amplification.

**Fully modular**
Every scanner capability is an independent module implementing one Go interface. Adding a new module is a single file with an `init()` registration call. Modules communicate exclusively via NATS JetStream — zero direct coupling.

---

## Architecture

```
Target ingestion (CLI / REST API)
         │
         ▼
    Orchestrator
    (NATS JetStream message bus)
         │
    ┌────┴──────────────────────┐
    │                           │
  Recon modules          Fingerprint modules
  DNS, ports, ASN        CMS, version, tech stack
    │                           │
    └──────────┬────────────────┘
               │
       Smart Nuclei Router  ◄─── ML re-ranker (Python/gRPC)
       Stage 1: metadata filter        │
       Stage 2: ML re-rank             │ online feedback
               │                       │
          Nuclei runner ───────────────┘
               │
       Findings store (PostgreSQL)
               │
       ┌───────┴────────┐
       │                │
  ML triage        Report generator
  FP reduction     Markdown / email
  clustering
```

---

## Modules

38 modules across 7 categories, all enabled/disabled independently:

| Category | Modules |
|---|---|
| Recon | subdomain_enumeration, dns_scanner, ip_lookup, reverse_dns_lookup, port_scanner, shodan_vulns, domain_expiration_scanner, dangling_dns_detector, removed_domain_existing_vhost |
| CMS | webapp_identifier, wp_scanner, wordpress_plugins, joomla_scanner, joomla_extensions, drupal_scanner, device_identifier |
| Brute force | bruter, admin_panel_login_bruter, wordpress_bruter, ftp_bruter, mysql_bruter, postgresql_bruter, ssh_bruter |
| Web | directory_index, robots, vcs, scripts_unregistered_domains, humble, api_scanner, lfi_detector, **graphql_scanner** ★ |
| Vulnerability | **smart_nuclei_router** ★, nuclei_module, ssh_bad_keys |
| Infra / Email | mail_dns_scanner |
| Extra | sql_injection_detector, subdomain_takeover, ssl_scanner, wpscan, xss_scanner |

★ = novel modules, not found in other open-source scanners

---

## Stack

| Component | Technology |
|---|---|
| Core scanner | Go 1.22 |
| Message bus | NATS JetStream |
| Task state | Redis |
| Findings store | PostgreSQL |
| ML middleware | Python 3.11 + gRPC |
| Deployment | Kubernetes / Helm |

---

## Quickstart

### Prerequisites

- Go 1.22+
- Docker + Docker Compose
- Nuclei templates (`nuclei -update-templates`)

### Run locally

```bash
git clone https://github.com/intelligent-ears/sift.git
cd sift

# Start infrastructure (NATS, Redis, PostgreSQL)
# See k8s/ for Helm-based deployment
docker compose up -d

# Run database migrations
go run ./cmd/sift migrate

# Start the orchestrator
go run ./cmd/orchestrator

# Add a target
go run ./cmd/sift scan --target example.com

# Bulk ingestion
go run ./cmd/sift scan --file targets.txt

# Query findings
go run ./cmd/sift findings --target example.com --severity HIGH

# Generate report
go run ./cmd/sift report --scan-id <id> --format markdown
```

### Deploy to Kubernetes

```bash
helm install sift ./k8s/charts/sift \
  --set config.nucleiTemplatesPath=/templates \
  --set ml.enabled=true
```

---

## Module interface

Every Sift module implements one interface:

```go
type Module interface {
    Name()     string
    Consumes() []TaskType   // NATS subjects this module subscribes to
    Produces() []TaskType   // task types it emits downstream
    Run(ctx context.Context, task Task) ([]Finding, []Task, error)
}
```

Registration is automatic via `init()`:

```go
func init() {
    registry.Register(&MyModule{})
}
```

The orchestrator discovers and subscribes all registered modules at startup. No manual wiring.

### Adding a module

1. Create `modules/<category>/<name>/<name>.go`
2. Implement `module.Module`
3. Call `registry.Register(&YourModule{})` in `init()`
4. Write tests in `<name>_test.go`

See [DESIGN.md](DESIGN.md) for the full architectural specification.

---

## Smart Nuclei Router

The two-stage template selector is Sift's primary technical contribution.

**Stage 1 — Deterministic metadata filter**

At startup, all Nuclei templates are indexed by `tags`, `technology`, `severity`, and port applicability. Given a fingerprinted target (e.g. `WordPress 6.1.2, PHP 7.4, ports 80/443`), Stage 1 returns ~150–400 relevant templates from 10,000+.

Tags `dos` and `fuzz` are always excluded. Tags `exposure`, `misconfiguration`, and `default-login` are always included regardless of target type.

**Stage 2 — ML re-ranker**

Candidates are scored by the ML middleware using per-template Beta distributions tracking historical hit rates. Updated online after every scan — the model improves continuously without retraining. The top N templates (default: 50, configurable via `NUCLEI_MAX_TEMPLATES`) are passed to the Nuclei runner.

Falls back to sorted Stage 1 results if the ML service is unavailable.

---

## GraphQL Scanner

8 checks covering attack surface not addressed by standard Nuclei templates:

| Check | Severity |
|---|---|
| Introspection enabled | HIGH |
| Field suggestion leakage | MEDIUM |
| Query depth limit missing | MEDIUM |
| Query complexity limit missing | MEDIUM |
| Batching enabled | LOW |
| Auth bypass on sensitive resolvers | HIGH |
| SQL injection via variables | HIGH |
| Alias-based query amplification | MEDIUM |

Probes `/graphql`, `/api/graphql`, `/graphql/v1`, `/v1/graphql`, `/query`, `/gql`. Each check is independently configurable via `GRAPHQL_CHECKS_ENABLED`.

---

## ML Middleware

The triage service is a Python gRPC microservice that runs alongside the Go core:

- Per-template Beta distribution hit-rate tracking (online, no batch retraining)
- False positive probability scoring per finding
- Finding clustering across targets using MiniBatchKMeans
- Model state persisted to Redis — survives pod restarts

The Go core calls it via gRPC. Scanning continues unaffected if the service is unavailable.

---

## Configuration

| Variable | Default | Description |
|---|---|---|
| `NATS_URL` | `nats://localhost:4222` | NATS JetStream URL |
| `POSTGRES_DSN` | — | PostgreSQL connection string |
| `REDIS_ADDR` | `localhost:6379` | Redis address |
| `NUCLEI_TEMPLATES_PATH` | `~/.nuclei-templates` | Nuclei templates directory |
| `NUCLEI_MAX_TEMPLATES` | `50` | Max templates after ML re-ranking |
| `SIFT_ML_ENDPOINT` | — | ML middleware gRPC endpoint (optional) |
| `GRAPHQL_CHECKS_ENABLED` | all | Comma-separated enabled GraphQL checks |
| `PORT_SCANNER_PORTS` | `21,22,25,80,443,3306,5432,6379,8080,8443` | Ports to scan |
| `SCANNING_PACKETS_PER_SECOND` | `5` | Port scan rate limit |

---

## Development

```bash
# Run all tests
go test ./...

# Build
go build ./...

# Regenerate gRPC stubs (requires protoc)
./scripts/compile-proto.sh

# List all modules and their status
go run ./cmd/sift modules list

# Enable / disable a module
go run ./cmd/sift modules enable graphql_scanner
go run ./cmd/sift modules disable ssh_bruter
```

---

## Roadmap

- [ ] Docker Compose for local development
- [ ] Real protobuf compilation + ML service Docker image
- [ ] Web dashboard
- [ ] SARIF report output
- [ ] OpenAPI/REST API for scan management
- [ ] IoT/embedded target module
- [ ] `sift-modules-extra` repo for non-Apache-licensed modules

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
