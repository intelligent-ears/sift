# Sift — Design Document
> Next-generation modular vulnerability scanner. From-scratch Go reimplementation
> advancing beyond Artemis (CERT-PL). Primary author: Arya.

---

## 1. Project Vision

Artemis demonstrated that large-scale automated vulnerability disclosure works. Sift advances
it in three concrete ways:

1. **Smart Nuclei Orchestration** — Artemis avoids broad Nuclei runs due to cost and noise.
   Sift makes Nuclei feasible at scale via a two-stage template selector: deterministic metadata
   filter (tag, technology, CVE version range) followed by an ML re-ranker that scores the
   filtered candidates using historical hit-rate, severity, and FP data.

2. **Online ML Triage Middleware** — A Python/gRPC microservice that reduces false positives,
   re-ranks findings by severity in target context, and clusters similar findings. It learns
   online — adapting within the first few hundred scans of a new deployment without retraining.

3. **GraphQL Scanner Module** — A novel module covering attack surface Artemis has no coverage
   for: introspection exposure, query depth abuse, batching attacks, auth bypass, and injection
   via variables.

**Target constituency:** National CERTs, bug bounty hunters, university research labs.
**Non-goal (v1):** IoT/embedded targets — designed as a future module, not in scope now.

---

## 2. Technology Stack

| Layer | Choice | Reason |
|---|---|---|
| Core language | Go | Concurrency, performance, single binary |
| Message bus | NATS JetStream | Go-native, persistent, K8s-friendly, lightweight |
| Task state | Redis | Fast ephemeral state, rate limiting |
| Findings store | PostgreSQL | Relational, queryable history |
| ML middleware | Python + gRPC | ML ecosystem lives in Python; clean Go boundary |
| Protobuf | proto3 | gRPC interface definition |
| Deployment | Helm / Kubernetes | K8s-ready from day one |
| Config | YAML + env vars | Standard Go config pattern |

---

## 3. Module System Contract

Every module is a Go struct implementing this interface. No exceptions.

```go
// pkg/module/module.go

type TaskType string

type Task struct {
    ID       string
    Type     TaskType
    Target   target.Target
    Payload  map[string]any
    ParentID string
}

type Finding struct {
    ID          string
    ModuleName  string
    Target      target.Target
    Severity    Severity        // CRITICAL, HIGH, MEDIUM, LOW, INFO
    Title       string
    Description string
    Evidence    map[string]any
    FalsePos    float32         // ML-assigned FP probability [0,1]
    CreatedAt   time.Time
}

type Module interface {
    Name()     string
    Consumes() []TaskType   // NATS subjects this module subscribes to
    Produces() []TaskType   // task types this module can emit downstream
    Run(ctx context.Context, task Task) ([]Finding, []Task, error)
}
```

Modules are registered in a central registry at startup via `init()` — no manual wiring.

```go
// internal/registry/registry.go
var modules []module.Module

func Register(m module.Module) {
    modules = append(modules, m)
}

func All() []module.Module { return modules }
```

Each module file calls `registry.Register(&MyModule{})` in its `init()`.

---

## 4. Full Module List

### 4a. Core modules (parity with Artemis)

| Module | Category | Consumes | Produces | Default |
|---|---|---|---|---|
| subdomain_enumeration | recon | domain | subdomain, url | on |
| dns_scanner | recon | domain | finding | on |
| ip_lookup | recon | domain, subdomain | ip | on |
| reverse_dns_lookup | recon | ip | finding | on |
| port_scanner | recon | ip | open_port, service | on |
| shodan_vulns | recon | ip | finding | off |
| domain_expiration_scanner | recon | domain | finding | on |
| dangling_dns_detector | recon | domain | finding | off |
| removed_domain_existing_vhost | recon | domain | finding | on |
| webapp_identifier | cms | url | cms_context | on |
| wp_scanner | cms | cms_context[wordpress] | finding | on |
| wordpress_plugins | cms | cms_context[wordpress] | finding | on |
| joomla_scanner | cms | cms_context[joomla] | finding | on |
| joomla_extensions | cms | cms_context[joomla] | finding | on |
| drupal_scanner | cms | cms_context[drupal] | finding | on |
| device_identifier | cms | service | device_context | on |
| bruter | brute | url | finding, url | on |
| admin_panel_login_bruter | brute | url | finding | off |
| wordpress_bruter | brute | cms_context[wordpress] | finding | on |
| ftp_bruter | brute | open_port[21] | finding | on |
| mysql_bruter | brute | open_port[3306] | finding | on |
| postgresql_bruter | brute | open_port[5432] | finding | on |
| ssh_bruter | brute | open_port[22] | finding | off |
| directory_index | web | url | finding | on |
| robots | web | url | finding, url | on |
| vcs | web | url | finding | on |
| scripts_unregistered_domains | web | url | finding | on |
| humble | web | url | finding | off |
| api_scanner | web | url | finding | off |
| lfi_detector | web | url | finding | on |
| smart_nuclei_router | vuln | url, cms_context, service | nuclei_job | on |
| nuclei_module | vuln | nuclei_job | finding | on |
| ssh_bad_keys | vuln | open_port[22] | finding | on |
| mail_dns_scanner | infra | domain | finding | on |
| sql_injection_detector | extra | url | finding | on |
| subdomain_takeover | extra | subdomain | finding | on |
| ssl_scanner | extra | open_port[443] | finding | on |
| wpscan | extra | cms_context[wordpress] | finding | off |
| xss_scanner | extra | url | finding | off |

### 4b. New modules (Sift originals)

| Module | Category | What it does |
|---|---|---|
| graphql_scanner | web | See Section 7 |
| smart_nuclei_router | vuln | Replaces Artemis's nuclei_router — see Section 6 |
| ml_triage | middleware | Online FP reduction + severity re-ranking — see Section 8 |

---

## 5. Repository Structure

```
sift/
├── cmd/
│   ├── sift/           # main CLI (scan, report, target management)
│   └── orchestrator/   # orchestrator daemon entrypoint
├── internal/
│   ├── orchestrator/   # task routing, dependency graph, NATS consumer mgmt
│   ├── ratelimiter/    # per-target, per-IP rate control (Redis-backed)
│   ├── store/          # PostgreSQL finding store interface + migrations
│   └── registry/       # module auto-discovery registry
├── modules/
│   ├── recon/
│   │   ├── subdomain_enumeration/
│   │   ├── dns_scanner/
│   │   ├── ip_lookup/
│   │   ├── port_scanner/
│   │   └── ...
│   ├── cms/
│   │   ├── webapp_identifier/
│   │   ├── wp_scanner/
│   │   └── ...
│   ├── brute/
│   ├── web/
│   │   ├── graphql_scanner/   # ★ new
│   │   └── ...
│   ├── vuln/
│   │   ├── smart_nuclei_router/  # ★ new
│   │   └── nuclei_module/
│   ├── infra/
│   └── extra/
├── ml/                 # Python ML microservice
│   ├── triage/
│   │   ├── classifier.py
│   │   ├── ranker.py
│   │   └── server.py   # gRPC server
│   └── api/
│       └── triage.proto
├── pkg/
│   ├── module/         # Module interface + Task/Finding types
│   ├── target/         # Target type (domain, ip, url, cidr)
│   ├── finding/        # Finding schema + severity enum
│   ├── nats/           # NATS client wrappers + subject naming conventions
│   └── config/         # Config struct + YAML/env loader
├── proto/
│   └── triage.proto    # protobuf definition for ML gRPC bridge
├── k8s/
│   ├── charts/sift/    # Helm chart
│   └── overlays/       # Kustomize overlays (dev/prod)
├── migrations/         # PostgreSQL schema migrations (golang-migrate)
├── scripts/
│   ├── start.sh
│   └── compile-proto.sh
├── DESIGN.md           # this file
├── go.mod
└── README.md
```

---

## 6. Smart Nuclei Router — Detailed Design

This is Sift's primary technical innovation. It replaces Artemis's `nuclei_router` with a
two-stage pipeline.

### Input
A `nuclei_job` task carrying the enriched target context:
```go
type NucleiJobPayload struct {
    URL         string
    CMSContext  *CMSContext           // nil if not a CMS target
    Services    []ServiceFingerprint  // from port_scanner
    OpenPorts   []int
    Headers     map[string]string     // from humble or raw HTTP
}
```

### Stage 1 — Deterministic Metadata Filter

At startup, Sift preprocesses all Nuclei templates into an in-memory index:

```go
type TemplateIndex struct {
    ByTag        map[string][]Template
    ByTechnology map[string][]Template
    ByCVE        map[string]Template
}
```

Each template's YAML metadata is parsed: `tags`, `metadata.verified`, `info.severity`,
affected product/version ranges. Given a `NucleiJobPayload`, Stage 1 queries the index and
returns candidate templates (typically 200–400 from 10k+) by:
- Tag intersection with detected technologies
- Version range overlap with detected software versions
- Port/service applicability

### Stage 2 — ML Re-ranker

The candidate list (template IDs + target context) is sent to the ML middleware via gRPC:

```go
scores, err := mlClient.RankTemplates(ctx, &proto.RankRequest{
    TemplateIds: candidateIDs,
    TargetContext: &proto.TargetContext{...},
})
```

The re-ranker returns a scored list. Sift takes the top N (default: 50, configurable).
The ML model updates its template scores as Nuclei results return — closing the feedback loop.

### Output
A filtered `[]string` of template IDs passed to `nuclei_module` for actual execution.

---

## 7. GraphQL Scanner Module — Detailed Design

No Nuclei templates cover this surface adequately. This is a native Go module.

### Checks (8 total)

| # | Check | Method |
|---|---|---|
| 1 | Introspection enabled | POST `{__schema{types{name}}}` — success = exposed |
| 2 | Field suggestion leakage | Typo query — "Did you mean X?" reveals schema without introspection |
| 3 | Query depth abuse | Deeply nested query — checks for depth limiting |
| 4 | Query complexity abuse | High field-count query — checks for complexity limiting |
| 5 | Batching attack | Array of operations in single request — checks if batching allowed |
| 6 | Auth bypass on sensitive resolvers | Query known admin/user resolver types without auth header |
| 7 | GraphQL injection via variables | Inject SQLi/NoSQLi payloads in variable fields |
| 8 | Alias-based query amplification | Use aliases to request same field N times |

### Endpoint Discovery
Before running checks, the module probes common GraphQL endpoints:
`/graphql`, `/api/graphql`, `/graphql/v1`, `/v1/graphql`, `/query`, `/gql`

It detects GraphQL responses by checking Content-Type and response body shape.

### Task Contract
```
Consumes: url
Produces: finding
```

Each check emits an independent Finding with evidence (request/response snippets).

---

## 8. ML Middleware — Detailed Design

A Python gRPC microservice. Go core calls it; it never initiates communication.

### gRPC interface (proto/triage.proto)
```protobuf
service TriageService {
  rpc RankTemplates(RankRequest) returns (RankResponse);
  rpc ScoreFinding(ScoreRequest) returns (ScoreResponse);
  rpc RecordOutcome(OutcomeRequest) returns (OutcomeResponse); // feedback
}
```

### Online learning model
- Per-template Bayesian hit-rate tracker (Beta distribution, updated per Nuclei result)
- Per-(template, target_type) FP rate tracker
- Severity re-ranker: logistic regression on [severity_base, target_context_features, historical_fp_rate]
- Finding clusterer: MiniBatchKMeans on finding embeddings (sentence-transformers, lightweight)

Model state is persisted to Redis so it survives pod restarts.

### Feedback loop
After each Nuclei run, `nuclei_module` calls `RecordOutcome` with:
- template_id, target_type, hit (bool), analyst_confirmed (bool, optional)

This updates the Beta distribution for that template — no retraining required.

---

## 9. NATS Subject Topology

```
sift.tasks.domain              # new domain ingested
sift.tasks.subdomain           # discovered subdomain
sift.tasks.ip                  # resolved IP
sift.tasks.url                 # discovered URL
sift.tasks.open_port.{port}    # open port (e.g. sift.tasks.open_port.22)
sift.tasks.service             # fingerprinted service
sift.tasks.cms_context.{cms}   # e.g. sift.tasks.cms_context.wordpress
sift.tasks.device_context      # identified device
sift.tasks.nuclei_job          # ready for nuclei execution
sift.findings                  # all findings (consumed by store + ML middleware)
sift.outcomes                  # ML feedback events
```

Modules subscribe to their `Consumes()` subjects as durable NATS JetStream consumers.
The orchestrator publishes to subject based on task type. No module talks to another directly.

---

## 10. Finding Schema (PostgreSQL)

```sql
CREATE TABLE findings (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    module_name   TEXT NOT NULL,
    target_id     UUID REFERENCES targets(id),
    severity      TEXT NOT NULL,           -- CRITICAL/HIGH/MEDIUM/LOW/INFO
    title         TEXT NOT NULL,
    description   TEXT,
    evidence      JSONB,
    false_pos_prob FLOAT DEFAULT 0.0,      -- ML-assigned [0,1]
    confirmed     BOOLEAN DEFAULT NULL,    -- analyst review
    created_at    TIMESTAMPTZ DEFAULT now(),
    scan_id       UUID REFERENCES scans(id)
);

CREATE TABLE targets (
    id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type    TEXT NOT NULL,   -- domain/ip/url/cidr
    value   TEXT NOT NULL,
    org     TEXT,
    tags    TEXT[]
);

CREATE TABLE scans (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at TIMESTAMPTZ,
    ended_at   TIMESTAMPTZ,
    status     TEXT,
    config     JSONB
);
```

---

## 11. Build Order

Build in this order — each step depends on the previous:

1. `pkg/target`, `pkg/finding`, `pkg/module` — data model first
2. `pkg/nats` — NATS client wrapper + subject naming
3. `internal/registry` — module registry
4. `internal/orchestrator` — task router skeleton (no real modules yet)
5. `modules/recon/subdomain_enumeration` + `dns_scanner` + `ip_lookup` + `port_scanner`
6. `modules/cms/webapp_identifier` — fingerprinting backbone
7. `modules/vuln/smart_nuclei_router` + `nuclei_module` — the core innovation
8. All remaining parity modules (brute, web, infra, extra)
9. `modules/web/graphql_scanner` — novel module
10. `ml/` — Python gRPC microservice
11. `proto/` + gRPC bridge between Go and Python
12. `internal/store` — PostgreSQL finding persistence
13. `cmd/sift` — CLI
14. `k8s/` — Helm chart

---

## 12. Key Design Decisions (rationale)

| Decision | Rationale |
|---|---|
| Go not Python | Performance, concurrency, single binary deployment, better K8s primitives |
| NATS not Karton/Celery | Go-native, lighter than Kafka, built-in persistence, works well on K8s |
| ML as Python sidecar | ML ecosystem is Python; gRPC boundary keeps it independently deployable |
| Online learning | General-purpose constituency means FP patterns vary per deployment; online avoids retraining |
| Two-stage Nuclei selection | Stage 1 is fast + deterministic; Stage 2 adds intelligence without blocking the pipeline |
| Module auto-registration via init() | Zero manual wiring — add a file, get a module |
| BSD license (core) | Matches Artemis; non-BSD tools go in a separate `sift-modules-extra` repo |
