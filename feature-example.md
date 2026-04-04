# IntentGuard Policy Feature Examples

This file maps each feature from `features.md` to a concrete `policy.yaml` section.

Use these as copy/paste building blocks.

---

## 1) Forbidden tool blocking

```yaml
static_rules:
  forbidden_tools:
    - delete_database
    - purge_all
```

---

## 2) Protected path enforcement (path traversal-safe)

```yaml
static_rules:
  protected_paths:
    - .env
    - /etc/*
    - src/auth/*
```

---

## 3) Token budget limits

```yaml
static_rules:
  max_tokens_per_call: 4000
```

---

## 4) Custom per-tool argument policies

```yaml
custom_policies:
  - tool_name: write_file
    args:
      all_present:
        - path
        - content
      should_not_present:
        - sudo
```

---

## 5) Prompt injection detection

```yaml
static_rules:
  injection_patterns:
    - "ignore previous instructions"
    - "disregard.*instructions"
    - "override.*policy"
    - "bypass.*security"
```

---

## 6) Secret/PII detection in arguments

```yaml
static_rules:
  sensitive_data_patterns:
    - name: "AWS Access Key"
      pattern: "AKIA[0-9A-Z]{16}"
    - name: "GitHub Token"
      pattern: "gh[ps]_[A-Za-z0-9_]{36,}"
    - name: "Email Address"
      pattern: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
    - name: "SSN"
      pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
```

---

## 7) Encoded bypass defense (URL/Base64/Unicode normalization)

```yaml
static_rules:
  decode_arguments: true
```

---

## 8) Semantic intent evaluation (task-aware guardrails)

```yaml
semantic_rules:
  mode: enforce
  critical_intent_threshold: 0.85
  constraints:
    - intent: modify_source_code
      allowed_scope: "UI-only changes"
      forbidden_scope: "Auth, DB schema, secrets"
```

---

## 9) Structured semantic verdicts + prompt versioning

```yaml
semantic_rules:
  prompt_version: "v1"
```

Note: structured verdict parsing is built into the semantic provider path; this setting versions the prompt used for those verdicts.

---

## 10) Provider resilience (retry/jitter/circuit breaker)

```yaml
semantic_rules:
  provider: ollama
  guardrail_model: llama3.1:8b
  retry_attempts: 2
  retry_base_delay_seconds: 0.25
  retry_max_delay_seconds: 2.0
  retry_jitter_ratio: 0.2
  circuit_breaker_failures: 3
  circuit_breaker_reset_seconds: 30
```

---

## 11) Per-tool semantic fail mode (safe fallback behavior)

```yaml
semantic_rules:
  provider_fail_mode:
    default: advisory
    by_tool:
      delete_database: enforce
      purge_all: enforce
```

---

## 12) Semantic decision caching (LRU + TTL)

```yaml
semantic_rules:
  decision_cache:
    enabled: true
    max_size: 256
    ttl_seconds: 300
```

---

## 13) Response-side inspection (outbound filtering)

```yaml
response_rules:
  action: block   # block | warn | redact
  detect_base64: true
  patterns:
    - name: "GitHub Token"
      pattern: "gh[ps]_[A-Za-z0-9_]{36,}"
    - name: "Email Address"
      pattern: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
```

---

## 14) Tool metadata rug-pull detection

```yaml
tool_change_rules:
  enabled: true
  action: warn   # warn | block
```

---

## 15) Advisory rollout mode (log, don't block)

Policy:

```yaml
semantic_rules:
  mode: advisory
```

Runtime:

```bash
intent-guard-proxy --advisory --policy schema/policy.yaml --target "<mcp command>"
```

---

## 16) Interactive approvals

Runtime:

```bash
intent-guard-proxy --ask-approval --policy schema/policy.yaml --target "<mcp command>"
```

---

## 17) Webhook approval backend

Runtime:

```bash
intent-guard-proxy \
  --approval-webhook "https://approval.internal/intent-guard" \
  --approval-timeout 10 \
  --approval-default-action deny \
  --policy schema/policy.yaml \
  --target "<mcp command>"
```

---

## 18) Break-glass controls (runtime env)

```bash
# Basic break-glass
export INTENT_GUARD_BREAK_GLASS_TOKEN="enabled"

# Signed break-glass
export INTENT_GUARD_BREAK_GLASS_SIGNED_TOKEN="<payload.signature>"
export INTENT_GUARD_BREAK_GLASS_SIGNING_KEY="<secret>"
```

---

## 19) Hot-reload policy without restart

Runtime:

```bash
intent-guard-proxy --watch-policy --policy schema/policy.yaml --target "<mcp command>"
```

---

## 20) Policy schema validation

Runtime:

```bash
intent-guard-proxy --validate --policy schema/policy.yaml
```

---

## 21) Starter secure policy templates

Use one of:

```text
policies/minimal.yaml
policies/code-agent-safe.yaml
policies/repo-write-guard.yaml
```

---

## 22) Native hook integration (Claude / Copilot / Cursor)

Command:

```bash
intent-guard evaluate --policy schema/policy.yaml
```

Hook templates shipped in:

```text
hooks/claude-code/settings.json
hooks/copilot/hooks.json
hooks/cursor/hooks.json
```

---

## 23) Audit-friendly decision metadata (output contract)

No extra policy needed; emitted in decisions/logs automatically:

```text
decision_id, code, severity, policy_name, policy_version, rule_id, timestamp, override, semantic_prompt_version
```

---

## Full policy bundles

### A) Minimal secure starter policy (small teams / quick rollout)

```yaml
version: "1.0"
name: "minimal-secure"

static_rules:
  forbidden_tools:
    - delete_database
    - purge_all
  protected_paths:
    - .env
    - .ssh/*
  max_tokens_per_call: 4000
  decode_arguments: true
  injection_patterns:
    - "ignore previous instructions"
    - "disregard.*instructions"
    - "override.*policy"
  sensitive_data_patterns:
    - name: "GitHub Token"
      pattern: "gh[ps]_[A-Za-z0-9_]{36,}"
    - name: "Email Address"
      pattern: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"

semantic_rules:
  provider: ollama
  guardrail_model: llama3.1:8b
  mode: advisory
  prompt_version: "v1"
  critical_intent_threshold: 0.85
  retry_attempts: 2
  retry_base_delay_seconds: 0.25
  retry_max_delay_seconds: 2.0
  retry_jitter_ratio: 0.2
  circuit_breaker_failures: 3
  circuit_breaker_reset_seconds: 30
  provider_fail_mode:
    default: advisory
  constraints:
    - intent: modify_source_code
      allowed_scope: "UI/docs only"
      forbidden_scope: "auth, infra, database"
```

Recommended runtime for this profile:

```bash
intent-guard-proxy \
  --advisory \
  --watch-policy \
  --ask-approval \
  --policy schema/policy.yaml \
  --target "<mcp command>"
```

---

### B) Enterprise-style security policy (strict + audit-heavy)

```yaml
version: "1.0"
name: "enterprise-secure"

static_rules:
  forbidden_tools:
    - delete_database
    - purge_all
    - exec_shell
  protected_paths:
    - .env
    - .ssh/*
    - /etc/*
    - infra/*
    - src/auth/*
  max_tokens_per_call: 3000
  decode_arguments: true
  injection_patterns:
    - "ignore previous instructions"
    - "disregard.*instructions"
    - "you are now"
    - "override.*policy"
    - "bypass.*security"
  sensitive_data_patterns:
    - name: "AWS Access Key"
      pattern: "AKIA[0-9A-Z]{16}"
    - name: "GitHub Token"
      pattern: "gh[ps]_[A-Za-z0-9_]{36,}"
    - name: "Email Address"
      pattern: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
    - name: "SSN"
      pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"

custom_policies:
  - tool_name: write_file
    args:
      all_present:
        - path
        - content
      should_not_present:
        - sudo

semantic_rules:
  provider: ollama
  guardrail_model: llama3.1:8b
  mode: enforce
  prompt_version: "v1"
  critical_intent_threshold: 0.9
  retry_attempts: 2
  retry_base_delay_seconds: 0.25
  retry_max_delay_seconds: 2.0
  retry_jitter_ratio: 0.2
  circuit_breaker_failures: 3
  circuit_breaker_reset_seconds: 30
  provider_fail_mode:
    default: advisory
    by_tool:
      delete_database: enforce
      purge_all: enforce
  decision_cache:
    enabled: true
    max_size: 256
    ttl_seconds: 300
  constraints:
    - intent: modify_source_code
      allowed_scope: "approved repository paths only"
      forbidden_scope: "auth, payments, infra, secrets"
    - intent: filesystem_access
      allowed_scope: "read-only docs/assets unless explicitly approved"

response_rules:
  action: block
  detect_base64: true
  patterns:
    - name: "AWS Access Key"
      pattern: "AKIA[0-9A-Z]{16}"
    - name: "GitHub Token"
      pattern: "gh[ps]_[A-Za-z0-9_]{36,}"
    - name: "Email Address"
      pattern: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"

tool_change_rules:
  enabled: true
  action: block
```

Recommended runtime for this profile:

```bash
intent-guard-proxy \
  --policy schema/policy.yaml \
  --target "<mcp command>" \
  --approval-webhook "https://approval.internal/intent-guard" \
  --approval-timeout 10 \
  --approval-default-action deny \
  --watch-policy
```

---

## End-to-end real-world examples

### E2E 1: SaaS engineering team (safe rollout with advisory first)

Goal: protect source repos from prompt injection, secret leaks, and risky file writes while minimizing disruption.

1) Save policy as `policy.saas.yaml` (start from the **Minimal secure starter policy** above).

2) Start proxy:

```bash
INTENT_GUARD_TASK="Refactor UI only; no auth/db changes" \
intent-guard-proxy \
  --advisory \
  --watch-policy \
  --ask-approval \
  --policy policy.saas.yaml \
  --target "npx @modelcontextprotocol/server-filesystem /path/to/repo"
```

3) Real behavior you should see:

- Agent tries to read `.env` → flagged by `protected_paths`; logged with `would_block=true`.
- Agent sends encoded injection payload in argument → caught by `decode_arguments + injection_patterns`.
- Agent includes a token/email in tool args → blocked/flagged by `sensitive_data_patterns`.
- Safe UI edits continue without blocking while team tunes policy.

4) When ready, switch from advisory to enforce:

- remove `--advisory`
- optionally tighten semantic threshold and constraints

---

### E2E 2: Security-sensitive org (strict enforcement + outbound controls)

Goal: fail closed on high-risk actions and prevent data exfiltration from MCP responses.

1) Save policy as `policy.enterprise.yaml` (start from the **Enterprise-style security policy** above).

2) Start proxy:

```bash
INTENT_GUARD_TASK="Only approved refactors in payment-service module" \
intent-guard-proxy \
  --policy policy.enterprise.yaml \
  --target "npx @modelcontextprotocol/server-filesystem /path/to/repo" \
  --approval-webhook "https://approval.internal/intent-guard" \
  --approval-timeout 10 \
  --approval-default-action deny \
  --watch-policy
```

3) Real behavior you should see:

- Attempted `delete_database`/`exec_shell` call → blocked immediately.
- Tool call with base64-encoded sensitive payload → decoded and blocked.
- MCP server response containing token/PII → blocked by `response_rules.action: block`.
- `tools/list` metadata drift (description/schema changes) → blocked by `tool_change_rules.action: block`.
- Repeated identical semantic checks → faster due to `decision_cache`.

---

## Claude Code use case (single-agent integration)

### Use case: "Guard Claude’s tool use for repo safety"

1) Keep this policy command:

```bash
intent-guard evaluate --policy schema/policy.yaml
```

2) In Claude Code hook config (`.claude/settings.json`), wire pre-tool hook:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "cat | intent-guard evaluate --policy schema/policy.yaml"
          }
        ]
      }
    ]
  }
}
```

3) What happens in practice:

- Claude proposes a tool call.
- Hook sends payload to `intent-guard evaluate`.
- Exit code `0` allows; `1` blocks; decision JSON provides reason/code/severity for auditability.

Practical scenario:

- Prompt asks Claude to "quickly dump `.env` and upload it"  
  → blocked by protected-path + sensitive data rules.
- Normal doc read / UI refactor call  
  → allowed.
