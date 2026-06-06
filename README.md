# Sift

**Sift** is a next-generation modular vulnerability scanner built in Go, designed for large-scale automated security assessments. It advances the ideas pioneered by [Artemis (CERT-PL)](https://github.com/CERT-Polska/Artemis) with three core innovations:

- **Context-aware Nuclei orchestration** — fingerprint targets first, then filter 10,000+ Nuclei templates to the relevant 50 using a two-stage metadata filter + ML re-ranker. Makes Nuclei feasible at scale.
- **Online ML triage middleware** — a Python/gRPC microservice that reduces false positives, re-ranks findings by severity, and clusters similar results. Adapts to new deployments without retraining.
- **GraphQL attack surface coverage** — 8 checks covering introspection exposure, query depth/complexity abuse, batching attacks, auth bypass, and injection via variables. Not covered by Artemis or standard Nuclei templates.

---

## Architecture

```
Target ingestion (CLI / REST API)
         │
         ▼
    Orchestrator  ←──────────────────────────────┐
    (NATS JetStream)                             │ feedback
         │                                       │
    ┌────┴─────────────────┐                     │
    │                      │                     │
  Recon              Fingerprint            ML Middleware
  modules            modules                (Python/gRPC)
    │                      │                     ▲
    └──────────┬───────────┘                     │
               │                                 │
        Smart Nuclei Router  ────────────────────┘
        (metadata filter + ML re-rank)
               │
          Nuclei runner
               │
        Findings store (PostgreSQL)
               │
        Report generator
```

All modules communicate exclusively via **NATS JetStream**. Every module implements a single Go interface — adding a new module is a single file with an `init()` registration call.

---

## Modules

Sift ships with 38 modules across 7 categories:

| Category | Modules |
|---|---|
| Recon | subdomain_enumeration, dns_scanner, ip_lookup, reverse_dns_lookup, port_scanner, shodan_vulns, domain_expiration_scanner, dangling_dns_detector, removed_domain_existing_vhost |
| CMS | webapp_identifier, wp_scanner, wordpress_plugins, joomla_scanner, joomla_extensions, drupal_scanner, device_identifier |
| Brute force | bruter, admin_panel_login_bruter, wordpress_bruter, ftp_bruter, mysql_bruter, postgresql_bruter, ssh_bruter |
| Web | directory_index, robots, vcs, scripts_unregistered_domains, humble, api_scanner, lfi_detector, **graphql_scanner** ★ |
| Vulnerability | **smart_nuclei_router** ★, nuclei_module, ssh_bad_keys |
| Infra / Email | mail_dns_scanner |
| Extra | sql_injection_detector, subdomain_takeover, ssl_scanner, wpscan, xss_scanner |

★ = novel modules not present in Artemis

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
- Docker + Docker Compose (for local infra)
- Nuclei templates (`nuclei -update-templates`)

### Run locally

```bash
git clone https://github.com/intelligent-ears/sift.git
cd sift

# Start infrastructure (NATS, Redis, PostgreSQL)
docker compose up -d

# Run database migrations
go run ./cmd/sift migrate

# Start the orchestrator
go run ./cmd/orchestrator

# In another terminal — add a target
go run ./cmd/sift scan --target example.com

# Query findings
go run ./cmd/sift findings --target example.com --severity HIGH
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

See [DESIGN.md](DESIGN.md) for the full architectural specification.

---

## Smart Nuclei Router

Artemis avoids broad Nuclei runs due to cost and noise at scale. Sift solves this with a two-stage template selector:

**Stage 1 — Deterministic metadata filter**

At startup, all Nuclei templates are indexed by `tags`, `technology`, `severity`, and port applicability. Given a fingerprinted target (e.g. `WordPress 6.1.2, PHP 7.4, ports 80/443`), Stage 1 queries the index and returns ~150–400 relevant templates from 10,000+.

Tags `dos` and `fuzz` are always excluded. Tags `exposure`, `misconfiguration`, and `default-login` are always included.

**Stage 2 — ML re-ranker**

The candidate list is scored by the ML middleware using per-template Bayesian hit-rate tracking (Beta distribution, updated online after each scan). The top N templates (default: 50, configurable) are passed to the Nuclei runner.

The re-ranker falls back gracefully if the ML service is unavailable — Stage 1 results are used in sorted order.

---

## GraphQL Scanner

Sift includes a dedicated GraphQL module covering attack surface not addressed by existing Nuclei templates:

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

Endpoint discovery probes `/graphql`, `/api/graphql`, `/graphql/v1`, `/v1/graphql`, `/query`, `/gql`. Each check is independently configurable via `GRAPHQL_CHECKS_ENABLED`.

---

## ML Middleware

The triage service is a Python gRPC microservice that:

- Tracks per-template hit rates using Beta distributions (online, no retraining)
- Scores findings for false positive probability
- Clusters similar findings across targets
- Persists model state to Redis — survives pod restarts

The Go core calls it via generated gRPC stubs. If the service is down, scanning continues unaffected — the ML layer is enhancement, not a dependency.

---

## Configuration

All configuration is via YAML file or environment variables:

| Variable | Default | Description |
|---|---|---|
| `NATS_URL` | `nats://localhost:4222` | NATS JetStream URL |
| `POSTGRES_DSN` | — | PostgreSQL connection string |
| `REDIS_ADDR` | `localhost:6379` | Redis address |
| `NUCLEI_TEMPLATES_PATH` | `~/.nuclei-templates` | Path to Nuclei templates directory |
| `NUCLEI_MAX_TEMPLATES` | `50` | Max templates per target after ML re-ranking |
| `SIFT_ML_ENDPOINT` | — | ML middleware gRPC endpoint (optional) |
| `GRAPHQL_CHECKS_ENABLED` | all | Comma-separated list of enabled GraphQL checks |
| `PORT_SCANNER_PORTS` | `21,22,25,80,443,3306,5432,6379,8080,8443` | Ports to scan |
| `SCANNING_PACKETS_PER_SECOND` | `5` | Rate limit for port scanning |

---

## Development

```bash
# Run all tests
go test ./...

# Build
go build ./...

# Lint
golangci-lint run

# Regenerate gRPC stubs (requires protoc)
./scripts/compile-proto.sh
```

### Adding a module

1. Create `modules/<category>/<name>/<name>.go`
2. Implement `module.Module`
3. Call `registry.Register(&YourModule{})` in `init()`
4. Add tests in `<name>_test.go`

No other wiring required. The orchestrator discovers and subscribes all registered modules at startup.

---

## Comparison with Artemis

| Feature | Artemis | Sift |
|---|---|---|
| Language | Python (Karton) | Go |
| Nuclei integration | Limited (cost/noise concern) | Full, context-filtered |
| Template selection | Manual/none | Two-stage: metadata filter + ML re-rank |
| False positive reduction | Manual review | Online ML triage |
| GraphQL scanning | ✗ | ✓ (8 checks) |
| Deployment | Docker Compose | Kubernetes-native (Helm) |
| Message bus | Karton (Redis-backed) | NATS JetStream |
| ML adaptation | ✗ | Online (no retraining) |

---

## Roadmap

- [ ] Real protobuf compilation + ML service Docker image
- [ ] IoT/embedded target module
- [ ] Web dashboard
- [ ] SARIF report output
- [ ] OpenAPI/REST API for scan management
- [ ] `sift-modules-extra` repo for non-Apache-licensed modules

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

## Acknowledgements

Inspired by [Artemis](https://github.com/CERT-Polska/Artemis) by CERT Polska. Nuclei templates by [ProjectDiscovery](https://github.com/projectdiscovery/nuclei-templates).
