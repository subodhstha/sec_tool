# Master Engineering & Operations Documentation: Vyomite DAST Platform
**Version:** 1.0 (Internal Release)  
**Target Audience:** Vyomite Engineering, Security, & DevOps Leadership  

---

## Table of Contents
1. [Part 1: Software Requirements Specification (SRS)](#part-1-software-requirements-specification-srs)
2. [Part 2: Technology Stack & Language Selection](#part-2-technology-stack--language-selection)
3. [Part 3: High-Level Architecture Design (HLD)](#part-3-high-level-architecture-design-hld)
4. [Part 4: Deployment & Operations Runbook](#part-4-deployment--operations-runbook)
5. [Part 5: Internal Rollout Playbook (Dogfooding)](#part-5-internal-rollout-playbook-dogfooding)

---

## Part 1: Software Requirements Specification (SRS)

### 1.1 Purpose
Defines requirements, constraints, and operational safeguards for the Vyomite DAST Platform to build a scalable, fault-tolerant, and safe automated web vulnerability scanner for internal enterprise dogfooding, followed by commercial release.

### 1.2 Scope
Cloud-native, continuous security assessment tool to map attack surfaces, maintain authenticated session states, and simulate real-world attack vectors (aligned with OWASP Top 10). Emphasizes zero-disruption scanning of internal QA/Staging environments via integrated circuit breakers, state-aware crawling, and developer-actionable SARIF defect reports directly into CI/CD workflows.

### 1.3 Functional Requirements (FR)

#### FR-1: Target Discovery and Mapping
- **FR-1.1 Headless Crawling:** Headless browser execution of JavaScript, DOM evaluation, and SPA mapping.
- **FR-1.2 API Schema Ingestion:** Parse OpenAPI/Swagger specifications and GraphQL introspection queries to map backend endpoints.
- **FR-1.3 Crawl Trap Prevention:** Normalize URL parameters (e.g. `/user/1` and `/user/2` into `/user/{id}`) and enforce strict tree-depth limits.

#### FR-2: Authentication State Management
- **FR-2.1 Macro Replay:** JSON-based authentication macro navigation (OAuth, MFA test seeds).
- **FR-2.2 Session Recovery:** Monitor Heartbeat URL; on 401 Unauthorized, pause fuzzer, execute macro to refresh JWT/Cookie, and resume scanning.

#### FR-3: Active Attack Simulation (Fuzzing)
- **FR-3.1 Context-Aware Injection:** Passively fingerprint target stack (React, Express, MySQL, etc.) and dynamically drop irrelevant payload categories.
- **FR-3.2 Out-of-Band (OOB) Detection:** External DNS/HTTP listener to verify blind vulnerabilities (Blind SSRF, Command Injection).
- **FR-3.3 Behavioral Latency Fuzzing:** Baseline server response time prior to executing time-based blind SQLi payloads.
- **FR-3.4 Payload Safety Profiles:** Support PASSIVE, LIGHT, STANDARD, AGGRESSIVE, and FULL profiles controlling active, time-based, OOB, severity, category, and payload-count policy.
- **FR-3.5 Reference Payload Coverage:** Maintain typed payload families derived from the attached PayloadsAllTheThings corpus, including SQLi, XSS, SSRF, XXE, SSTI, GraphQL, JWT, CORS, file upload, and file inclusion vectors.

#### FR-4: Safety Safeguards and Circuit Breakers (Critical)
- **FR-4.1 Domain Verification:** Scan requires verification token in target DNS TXT records or `/.well-known/` directory.
- **FR-4.2 Safe HTTP Verb Enforcement:** Drop state-changing requests (POST, PUT, DELETE, PATCH) indicating destructive actions based on semantic regex matching (e.g. `/delete`).
- **FR-4.3 5xx Circuit Breaker:** Pause scan immediately if target server returns consecutive 5xx status codes.
- **FR-4.4 Dynamic Latency Back-off:** Throttle requests-per-second if target response times exceed baseline thresholds.

#### FR-5: Reporting and Integration
- **FR-5.1 Vulnerability Deduplication:** Hash parameter name, injection context, and vulnerability type to group identical flaws across URLs.
- **FR-5.2 Developer-Native Output:** Export findings in Static Analysis Results Interchange Format (SARIF).
- **FR-5.3 Operations Dashboard:** Provide scan creation controls for safety profile, active fuzzing, concurrency, target categories, and verification; expose searchable cross-scan vulnerability findings and scan policy context.

---

## Part 2: Technology Stack & Language Selection

Polyglot microservices architecture tailored for each workload:

- **Core Fuzzing Engine & HTTP Workers:** Go (Golang) — lightweight goroutines, concurrency (10,000+ conn/sec), low memory footprint, static binary deployment (`net/http`, `go-resty`, `PuerkitoBio/goquery`, `projectdiscovery/rawhttp`).
- **DOM Crawler (Headless Browser):** TypeScript / Node.js — Playwright / Puppeteer native integration for SPAs.
- **API Gateway & Backend:** Go (Golang) — Gin or Fiber, fast JSON routing to RabbitMQ / Kafka.
- **Frontend Dashboard:** TypeScript / React with Next.js — interactive scan feeds, payload-policy controls, searchable cross-scan findings, SARIF reports, and scan detail evidence.

---

## Part 3: High-Level Architecture Design (HLD)

### 3.1 System Overview
Web-Queue-Worker microservices architecture separating user-facing API operations from synchronous execution of vulnerability scans.

### 3.2 Core Components
- **Web Tier (API Gateway):** Handles authentication, API requests, drops scan jobs into the message broker, and returns `202 Accepted`.
- **Message Broker:** RabbitMQ or Apache Kafka with queues (`scan_jobs`, `results_processing`).
- **Worker Pool (Scanning Engine):** Consumes `scan_jobs`, executes network requests, evaluates logic using Service-Repository Pattern.
- **Out-of-Band (OOB) Listener:** Custom Go DNS/HTTP server logging callbacks to Redis.

**Current repository baseline:** The API gateway and worker use Go `net/http`; the default local wiring uses the shared in-memory broker and store abstractions. Docker Compose provisions RabbitMQ, Redis, and PostgreSQL for the deployment target, but production adapters and persistence cutover remain an operations milestone rather than an assumption of the local development path.

### 3.3 Security Architecture
- **Credentials:** HashiCorp Vault management with short-lived IAM tokens.
- **Encryption:** AES-256 for data at rest (PostgreSQL), TLS 1.3 / mTLS in transit.
- **Sanitization:** Regex-based masking function to strip Authorization headers and session cookies before persisting request/response logs.

### 3.4 Payload Execution Contract
- Payloads are selected by injection context and target category, with endpoint headers and refreshed authentication headers propagated into each request.
- JSON and GraphQL payloads are serialized as valid JSON; XML, form, cookie, header, path, and multipart contexts use transport-specific request construction.
- Content-difference, status-code, redirect-location, response-header, reflection, and error-pattern detectors compare injected responses against a baseline where appropriate.
- Payload execution is bounded by `MaxConcurrentRequests`, target-scoped deduplication, circuit-breaker telemetry, and profile policy.

---

## Part 4: Deployment & Operations Runbook

### 4.1 Infrastructure Requirements
- Environment: Internal VPC
- Orchestration: Kubernetes (EKS / GKE)
- Databases: PostgreSQL 15+, RabbitMQ (or AWS SQS), Redis

### 4.2 Autoscaling (KEDA)
- Trigger: RabbitMQ Queue Length (`scan_jobs`)
- Min Pods: 1 standby pod (0 pending jobs)
- Scale Up: 1 pod per 5 jobs (max 50 pods)

### 4.3 Incident Response & Playbooks
- **Target DoS:** Verify 5xx Circuit Breaker is active. Issue `POST /api/v1/scans/{id}/abort`. Reduce max threads per target from 50 to 15.
- **Unintended Data Deletion:** Abort scan. Verify Safe Mode. Add endpoint to global VPC regex blocklist.

---

## Part 5: Internal Rollout Playbook (Dogfooding)

- **Phase 1: Safe Passive Discovery (Weeks 1-3):** Staging & QA. Fuzzing DISABLED. Crawling and header/tech-stack analysis only.
- **Phase 2: Restricted Active Fuzzing (Weeks 4-6):** UAT environments with disposable data. Max 20 req/s, Safe Verbs Mode (no DELETEs). Verify OOB listener.
- **Phase 3: Developer Pipeline Integration (Weeks 7-9):** CI/CD (GitHub Actions / GitLab CI). Post SARIF report comments directly on PRs.
- **Phase 4: Production Scanning with Guardrails (Weeks 10+):** Off-peak hours, read-only fuzzing, rate limited to 10 req/s.
