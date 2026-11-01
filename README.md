# Vyomite DAST Platform
**Enterprise-Grade Continuous Security Assessment & Fuzzing Engine**  
*Version 1.0 (Dogfooding Release)*

---

## Architectural Monorepo Structure

```
d:\new/
├── docs/
│   └── VYOMITE_DAST_SPEC.md              # Master Engineering & Operations Spec
├── pkg/
│   └── models/                           # Shared Go Domain & Data Models
│       ├── scan.go                       # ScanJob, ScanConfig, AuthMacro models
│       ├── vulnerability.go              # VulnerabilityFinding & FR-5.1 Dedup Hash
│       ├── sarif.go                      # FR-5.2 SARIF v2.1.0 generator
│       ├── circuit_breaker.go            # FR-4.3 & FR-4.4 CB telemetry models
│       ├── broker.go                     # Message Broker abstraction & queue
│       └── store.go                      # Scan & Finding persistence repository
├── services/
│   ├── api-gateway/                      # Go REST API Gateway (:8080)
│   │   ├── cmd/main.go                   # HTTP routing (202 Accepted, SARIF export)
│   │   └── internal/verification/        # FR-4.1 Domain Verification (DNS TXT / well-known)
│   ├── scan-worker/                      # Go Scanning & Fuzzing Engine
│   │   ├── cmd/main.go                   # Queue consumer & orchestration
│   │   ├── internal/circuitbreaker/      # FR-4.3 5xx Breaker & FR-4.4 Latency Back-off
│   │   ├── internal/filter/              # FR-4.2 Safe HTTP Verb Enforcement
│   │   ├── internal/sanitizer/           # Part 3.3 Credential Masking & Token Redaction
│   │   ├── internal/auth/                # FR-2.1 Macro Replay & FR-2.2 Heartbeat Recovery
│   │   └── internal/fuzzer/              # FR-3.1 Fingerprinting, FR-3.2 OOB, FR-3.3 Latency SQLi
│   ├── oob-listener/                     # Go Out-of-Band Callback Server (:8082)
│   │   └── cmd/main.go                   # FR-3.2 Blind SSRF & Command Injection listener
│   ├── crawler/                          # TypeScript / Node.js Headless Crawler (:3001)
│   │   └── src/
│   │       ├── crawler.ts                # FR-1.1 SPA Mapping & Form discovery
│   │       ├── normalizer.ts             # FR-1.3 Crawl Trap Prevention (/user/{id})
│   │       ├── api_parser.ts             # FR-1.2 OpenAPI & GraphQL Introspection ingestion
│   │       └── server.ts                 # Express microservice
│   └── dashboard/                        # TypeScript + React + Vite Web UI (:3000)
│       └── src/
│           ├── App.tsx                   # Main assessment feed & workspace
│           ├── index.css                 # Dark high-tech design system
│           └── components/
│               ├── CircuitBreakerCard.tsx # FR-4.3 / FR-4.4 real-time safety meter
│               ├── VulnerabilityFeed.tsx  # FR-5.1 deduplicated flaws & evidence
│               ├── ScanModal.tsx          # FR-4 safeguard configuration
│               └── SarifViewerModal.tsx   # FR-5.2 SARIF 2.1.0 viewer & exporter
├── deployments/
│   ├── docker-compose.yml                # Multi-service local cluster
│   └── k8s/
│       └── keda-scaledobject.yaml        # Part 4.2 KEDA autoscaling definition
└── go.work                               # Go 1.22+ workspace
```

---

## SRS & Feature Traceability Matrix

| Requirement | Implementation Component | Verification Test |
| :--- | :--- | :--- |
| **FR-1.1 Headless Crawling** | `services/crawler/src/crawler.ts` | DOM link and form input extractor |
| **FR-1.2 Schema Ingestion** | `services/crawler/src/api_parser.ts` | OpenAPI 3.0 & GraphQL introspection parser |
| **FR-1.3 Crawl Trap Prevention** | `services/crawler/src/normalizer.ts` | `normalizer.test.ts` (Passed) |
| **FR-2.1 Macro Replay** | `services/scan-worker/internal/auth` | JSON-based authentication flow |
| **FR-2.2 Session Recovery** | `services/scan-worker/internal/auth` | Heartbeat URL 401 pause-refresh-resume |
| **FR-3.1 Context Injection** | `services/scan-worker/internal/fuzzer` | Passive tech-stack fingerprinting |
| **FR-3.2 OOB Detection** | `services/oob-listener/cmd/main.go` | External UUID correlation callback listener |
| **FR-3.3 Behavioral Latency** | `services/scan-worker/internal/fuzzer` | Baseline vs delay differential evaluation |
| **FR-4.1 Domain Verification** | `services/api-gateway/internal/verification` | DNS TXT and `/.well-known/` verification |
| **FR-4.2 Safe Verb Enforcement** | `services/scan-worker/internal/filter` | `safe_verbs_test.go` (Passed) |
| **FR-4.3 5xx Circuit Breaker** | `services/scan-worker/internal/circuitbreaker` | `circuit_breaker_test.go` (Passed) |
| **FR-4.4 Latency Back-off** | `services/scan-worker/internal/circuitbreaker` | `circuit_breaker_test.go` (Passed) |
| **FR-5.1 Vulnerability Dedup** | `pkg/models/vulnerability.go` | `vulnerability_test.go` (Passed) |
| **FR-5.2 SARIF Output** | `pkg/models/sarif.go` | `sarif_test.go` (Passed) |

---

## Quickstart & Local Execution

### Option 1: Docker Compose (Full Cluster)
```bash
docker compose up --build
```
This spins up RabbitMQ (with management UI on `:15672`), Redis, PostgreSQL, the Go API Gateway (`:8080`), Go Scan Worker, Node.js Crawler (`:3001`), OOB Listener (`:8082`), and Web Dashboard (`:3000`).

### Option 2: Running Services Individually

1. **Start the API Gateway:**
   ```bash
   cd services/api-gateway
   go run cmd/main.go
   ```
2. **Start the OOB Listener:**
   ```bash
   cd services/oob-listener
   go run cmd/main.go
   ```
3. **Start the Headless Crawler:**
   ```bash
   cd services/crawler
   npm start
   ```
4. **Start the Scan Worker:**
   ```bash
   cd services/scan-worker
   go run cmd/main.go
   ```
5. **Start the Web Dashboard:**
   ```bash
   cd services/dashboard
   npm run dev
   ```

---

## API Reference

### 1. Launch Assessment
```http
POST /api/v1/scans
Content-Type: application/json

{
  "target_url": "https://staging.internal.vyomite.com",
  "config": {
    "safe_mode": true,
    "max_rps": 20,
    "max_depth": 3,
    "verification_token": "vyomite-dev-token",
    "consecutive_5xx_cap": 5,
    "baseline_latency_ms": 200,
    "active_fuzzing": true
  }
}
```
**Response:** `202 Accepted`

### 2. Abort Scan (Scenario A Incident Response)
```http
POST /api/v1/scans/{scan_id}/abort
```

### 3. Fetch SARIF v2.1.0 Defect Report (CI/CD Export)
```http
GET /api/v1/scans/{scan_id}/results?format=sarif
```
