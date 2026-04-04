# IntentGuard — Security Features (OSS Launch)

IntentGuard is a policy enforcement layer for AI agents and MCP tool calls.  
It focuses on **preventing dangerous actions before execution**, **detecting data leakage**, and **adding human/control-plane safety for high-risk operations**.

## 1) Pre-execution attack prevention

- **Forbidden tool blocking** (`forbidden_tools`)
- **Protected path enforcement** (`protected_paths`) with traversal-safe normalization
- **Token budget limits** (`max_tokens_per_call`)
- **Custom per-tool argument policies** (`custom_policies`)
- **Prompt injection detection** in tool-call arguments
- **Secret/PII detection** in arguments (keys, tokens, emails, SSN patterns)
- **Encoded bypass defense** with URL decode + Base64 decode + Unicode normalization before matching

## 2) Semantic safety (task-aware guardrails)

- **Semantic intent evaluation** against task context and constraints
- **Structured JSON semantic verdicts** (`safe`, `score`, `reason`) for deterministic parsing
- **Prompt versioning** (`semantic_rules.prompt_version`) for auditability/change control
- **Provider resilience**: retries, jitter, circuit breaker, and per-tool fail modes
- **Decision caching (LRU + TTL)** for repeated semantic checks
- **Live semantic test path using `llama3.1:8b`** (updated from classifier-only setup)

## 3) Response-side protection (outbound)

- **Response inspection before forwarding to agent**
- Policy-driven actions: **block / warn / redact**
- Pattern checks for secrets/PII in MCP server responses
- Encoded payload checks on responses (including Base64 scenarios)

## 4) Tool integrity / rug-pull protection

- Snapshot MCP `tools/list` metadata (name, description, input schema)
- Detect drift across runs and either:
  - **Warn** on change, or
  - **Block** changed tool metadata

## 5) Safety controls for real-world operations

- **Advisory mode** (log violations, do not block) for low-risk rollout
- **Interactive approvals** (`--ask-approval`)
- **Webhook-based approval backend** for non-interactive workflows
- **Break-glass controls** (including signed token path)
- **Hot-reload policy** without proxy restart
- **Policy schema validation** (`--validate`)
- **Starter secure policy templates**

## 6) Works where developers already are

- **Native hook integration** via `intent-guard evaluate`
- Hook templates shipped for:
  - Claude Code
  - GitHub Copilot
  - Cursor
- Standard MCP proxy mode remains available

## 7) Auditability and reliability

- Stable decision contract with metadata:
  - `decision_id`, `code`, `severity`, `policy_name`, `policy_version`, `rule_id`, `timestamp`, `override`, `semantic_prompt_version`
- Integration coverage for stdio proxy pipeline and policy enforcement behavior

---

### Security outcome for LLM apps

Using IntentGuard helps teams:

- Reduce prompt-injection-driven misuse
- Prevent secret/PII leaks in both requests and responses
- Catch encoded payload bypass attempts
- Detect tool definition drift/rug-pulls
- Roll out safely (advisory → enforce) with audit-ready decision logs
