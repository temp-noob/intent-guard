# GitHub Issue Drafts

These are ready-to-paste issue titles and bodies based on the prioritized roadmap.

## 1) Add a stable decision contract (codes, severity, policy metadata, override info)

**Title**
`Add stable decision contract with policy metadata and override fields`

**Body**
### Why
Infra needs machine-readable enforcement + analytics, not just `allowed/reason`.

### Acceptance Criteria
- `GuardDecision` includes: `decision_id`, `code`, `severity`, `policy_name`, `policy_version`, `rule_id`, `timestamp`
- Support `override` fields when approved (who/why/ttl)

---

## 2) Add OpenTelemetry + metrics (latency, allow/block, approval, provider errors)

**Title**
`Add OpenTelemetry spans and decision/provider metrics`

**Body**
### Why
Makes the guard operable and measurable for safe adoption.

### Acceptance Criteria
- OTEL spans around each `tools/call` evaluation
- Prometheus/OTEL metrics: `intent_guard_decisions_total{allowed,code,tool}`, `intent_guard_eval_latency_ms`, `intent_guard_provider_errors_total`

---

## 3) Replace terminal approval with pluggable non-interactive approval backends

**Title**
`Implement pluggable non-interactive approval backends`

**Body**
### Why
Terminal prompt does not scale beyond local development.

### Acceptance Criteria
- Approval interface supports webhook callback, timeout, default action
- Add break-glass token option (env var / signed token) for CI

---

## 4) Semantic provider hardening (timeouts, retries, circuit breaker, fail-open/closed per tool)

**Title**
`Harden semantic provider with retries, circuit breaker, and per-tool fail mode`

**Body**
### Why
Infra teams require predictable behavior during provider outages.

### Acceptance Criteria
- Configurable per-tool behavior when semantic provider fails
- Clear config: `semantic_rules.mode = off|enforce|advisory`
- Circuit breaker after N failures

---

## 5) Policy validation + policy compiler

**Title**
`Add policy schema validation and deterministic policy compiler`

**Body**
### Why
YAML policies need schema validation and deterministic normalization.

### Acceptance Criteria
- `intent-guard policy validate schema/policy.yaml`
- Validation fails on unknown keys/types with helpful errors
- Optional normalized compiled policy JSON output

---

## 6) First-class resource mapping for tools (explicit arg mapping)

**Title**
`Add explicit per-tool resource argument mapping`

**Body**
### Why
Safe enforcement requires accurate knowledge of tool resource targets.

### Acceptance Criteria
- Policy supports per-tool argument mapping (e.g. `path_arg: params.arguments.path`)
- Resource types include at least `filesystem.path`, `repo.branch`

---

## 7) Policy templates for code agents (ready-to-run packs)

**Title**
`Ship starter policy templates for code-agent usage`

**Body**
### Why
Templates accelerate organic developer adoption.

### Acceptance Criteria
- Add templates in `policies/`: `code-agent-safe.yaml`, `repo-write-guard.yaml`
- Docs include quick-start: “pick one, change 3 lines”

---

## 8) Advisory mode with reporting-only (no blocking)

**Title**
`Add advisory/reporting mode with no enforcement blocking`

**Body**
### Why
Lets teams deploy safely first and gather PMF data.

### Acceptance Criteria
- Proxy passes through but logs `would_block=true`
- Summary report CLI includes top violations, risky tools, protected-path hits

---

## 9) Central policy distribution mechanism (control plane v0)

**Title**
`Add central policy distribution v0 with signature verification`

**Body**
### Why
Infra teams need centralized policy distribution instead of per-repo YAML sprawl.

### Acceptance Criteria
- Load policy from local file OR HTTPS URL OR S3/GCS (choose first target)
- Verify policy signature (HMAC or public key)
- Support policy version pinning

---

## 10) HTTP gateway mode (in addition to MCP stdio proxy)

**Title**
`Add HTTP gateway mode for network-deployable evaluation`

**Body**
### Why
Enterprise platform teams need a service mode in addition to stdio proxy.

### Acceptance Criteria
- Run as a service receiving tool-call evaluation requests
- Usable by embedded SDK clients

---

## 11) Audit log format + export sinks

**Title**
`Define stable audit log schema and add export sinks`

**Body**
### Why
Enterprise adoption requires stable, exportable audit logs.

### Acceptance Criteria
- Document stable JSON audit log schema
- Optional sinks: file, stdout, webhook, OTEL log exporter
