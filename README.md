# IntentGuard

IntentGuard is a Python guardrail layer for MCP tool calls. It runs as a proxy between an agent client and an MCP server, enforcing both static policy checks and optional semantic intent checks before a tool call is forwarded.

## What is implemented (MVP)

The current implementation covers all 4 roadmap phases from `agent.md`:

1. **CLI Interceptor (Phase 1)**  
   `intent_guard/proxy.py` + `intent_guard/sdk/mcp_proxy.py` implement a stdio proxy that intercepts `tools/call` JSON-RPC requests and can block/allow calls.
2. **Static Engine (Phase 2)**  
   `intent_guard/sdk/engine.py` loads YAML policy and enforces:
   - `forbidden_tools`
   - `protected_paths` (glob/fnmatch style)
   - `max_tokens_per_call`
   - `custom_policies` (tool-specific argument requirements/forbidden arguments)
3. **Semantic Guardrail Providers (Phase 3)**  
   `intent_guard/sdk/providers.py` supports:
   - `OllamaProvider` (`POST /api/generate`)
   - `LiteLLMProvider` (`litellm.completion`) using `LLM_MODEL` and `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` from env
   Both providers include retries (exponential backoff + jitter) and a circuit breaker.
4. **Pause & Resume Feedback Loop (Phase 4)**  
   `terminal_approval_prompt` provides interactive approval for flagged calls (`Allow? [y/N]`).

## Repository layout

```text
intent_guard/
├── __init__.py
├── proxy.py
└── sdk/
    ├── __init__.py
    ├── engine.py
    ├── mcp_proxy.py
    └── providers.py
schema/
└── policy.yaml
tests/
├── conftest.py
└── test_integration_phases.py
```

## Installation

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Run tests

```bash
.venv/bin/pytest -q
```

Run live Ollama semantic tests only (requires local Ollama + `llama3.1:8b` available):

```bash
.venv/bin/pytest -q -m runOllamaProvider
```

If local model responses are slow, increase timeout (seconds):

```bash
OLLAMA_TIMEOUT_SECONDS=120 .venv/bin/pytest -q -m runOllamaProvider
```

The live semantic suite defaults to `OLLAMA_RAW=false` and bounded generation tuned for `llama3.1:8b`. You can tune:

```bash
OLLAMA_TIMEOUT_SECONDS=60 OLLAMA_NUM_PREDICT=256 OLLAMA_RAW=false \
  .venv/bin/pytest -q -m runOllamaProvider
```

Integration tests cover all phases:
- phase 1: interception and logging behavior
- phase 2: static policy blocking
- phase 3: semantic provider flow (mocked Ollama HTTP call)
- phase 4: approval allow/deny behavior

## Policy file

Use `schema/policy.yaml` as a starting point:

```yaml
static_rules:
  forbidden_tools: ["delete_database", "purge_all"]
  protected_paths: ["/etc/*", ".env", "src/auth/*"]
  max_tokens_per_call: 4000

custom_policies:
  - tool_name: write_file
    args:
      all_present: ["path", "content"]
      should_not_present: ["sudo"]

semantic_rules:
  provider: ollama # or litellm
  mode: enforce # off | enforce | advisory
  prompt_version: "v1"
  guardrail_model: llama3.1:8b
  critical_intent_threshold: 0.85
  retry_attempts: 2
  retry_base_delay_seconds: 0.25
  retry_max_delay_seconds: 2.0
  retry_jitter_ratio: 0.2
  circuit_breaker_failures: 3
  circuit_breaker_reset_seconds: 30
  provider_fail_mode:
    default: advisory # fail-open
    by_tool:
      delete_database: enforce # fail-closed
  constraints:
    - intent: modify_source_code
      allowed_scope: Actions must only affect UI components or styles.
      forbidden_scope: Should not modify database schemas or auth logic.
```

## CLI usage

```bash
INTENT_GUARD_TASK="Only update frontend styles" \
python -m intent_guard.proxy \
  --policy schema/policy.yaml \
  --target "npx @modelcontextprotocol/server-filesystem /path/to/repo" \
  --model llama3.1:8b \
  --approval-webhook "https://approval.internal/intent-guard" \
  --approval-timeout 10 \
  --approval-default-action deny
```

### Flags
- `--policy`: YAML policy path
- `--target`: target MCP server command
- `--model`: optional Ollama model name for semantic checks
- `--task`: optional task context (or set `INTENT_GUARD_TASK`)
- `--ask-approval`: prompt user before allowing flagged calls
- `--approval-webhook`: call this webhook for non-interactive approval decisions
- `--approval-timeout`: timeout (seconds) for webhook approvals
- `--approval-default-action`: `allow` or `deny` when webhook approval times out/fails

## Native hook integration

IntentGuard can run as the policy engine behind native hooks in Claude Code, Copilot, and Cursor.

### Evaluate command

Use the unified command:

```bash
intent-guard evaluate --policy schema/policy.yaml
```

Input:
- Reads a hook payload JSON object from stdin
- Supports generic keys like `tool_name`, `arguments`, `task_context`
- Also supports nested payloads (`params.name`, `params.arguments`) and common aliases (`tool_input`, `args`, `prompt`)

Output:
- Prints a `GuardDecision` JSON object to stdout
- Exit code `0` for allow, `1` for block, `2` for invalid input

### Hook config templates

Template files are shipped under `hooks/`:
- `hooks/claude-code/settings.json`
- `hooks/copilot/hooks.json`
- `hooks/cursor/hooks.json`

Each template invokes:

```bash
cat | intent-guard evaluate --policy schema/policy.yaml
```

This lets platform-native hooks call IntentGuard directly instead of wrapping only MCP servers.

## Encoded payload detection

Static checks can decode and normalize argument payloads before matching:
- URL decoding
- Unicode normalization (NFKC)
- Base64 decoding (when valid)

Enable or disable via:

```yaml
static_rules:
  decode_arguments: true
```

When enabled, injection, sensitive-data, and protected-path checks run against decoded variants to catch obfuscated bypasses.

## Response-side inspection

IntentGuard can inspect MCP server responses before forwarding them to the client.

Configure `response_rules` in policy:

```yaml
response_rules:
  action: block # block | warn | redact
  detect_base64: true
  patterns:
    - name: "GitHub Token"
      pattern: "gh[ps]_[A-Za-z0-9_]{36,}"
```

Behavior:
- `block`: return JSON-RPC error and suppress original response
- `warn`: forward response and log warning decision
- `redact`: redact matched text and forward sanitized response

## Tool description change detection (rug-pull protection)

IntentGuard can snapshot MCP `tools/list` metadata and detect changes over time.

Configure:

```yaml
tool_change_rules:
  enabled: true
  action: warn # warn | block
```

Behavior:
- On first `tools/list`, stores snapshot in `.intent-guard/tool-snapshots/<server-hash>.json`
- On subsequent `tools/list`, compares `name`, `description`, and `inputSchema`
- `warn`: log warning and continue
- `block`: block response when drift is detected

### Semantic mode and provider failure behavior

`semantic_rules.mode` controls normal semantic enforcement:
- `off`: semantic check disabled
- `enforce`: semantic failures block tool calls
- `advisory`: semantic failures are logged as warnings but calls are allowed

`semantic_rules.provider_fail_mode` controls behavior when semantic provider is unavailable:
- supports `default` and per-tool `by_tool` override
- values use the same mode set: `off|enforce|advisory`

Behavior matrix for tool criticality tiers (example mapping):

| Tool tier | `provider_fail_mode` | Outcome on provider outage |
|---|---|---|
| Critical tools | `enforce` | Fail-closed (block + approval required) |
| Standard tools | `advisory` | Fail-open with warning decision |
| Low-risk tools | `off` | Fail-open without warning severity |

Define tiers by assigning tools in `provider_fail_mode.by_tool`.

`semantic_rules.prompt_version` is copied into every semantic decision and log entry as `semantic_prompt_version` so prompt changes are auditable.

### Semantic decision caching

To reduce repeated provider calls for identical semantic evaluations:

```yaml
semantic_rules:
  decision_cache:
    enabled: true
    max_size: 256
    ttl_seconds: 300
```

Cache key uses `(tool_name, arguments, task_context)`. Static checks always run; only semantic verdicts are cached.

### LiteLLM provider

To use the API provider, set in `.env` (or process env):

```bash
LLM_MODEL=claude-3-5-sonnet-20241022
ANTHROPIC_API_KEY=...
# or OPENAI_API_KEY=...
```

Then set `semantic_rules.provider: litellm` (or just set `LLM_MODEL` and omit explicit provider).

### CI break-glass options

- `INTENT_GUARD_BREAK_GLASS_TOKEN`: if set, flagged calls are auto-approved with override metadata.
- `INTENT_GUARD_BREAK_GLASS_SIGNED_TOKEN` + `INTENT_GUARD_BREAK_GLASS_SIGNING_KEY`: optional HMAC-signed break-glass token for CI. Token format is `<base64url(json payload)>.<base64url(signature)>` where signature is `HMAC-SHA256(payload_part, signing_key)` and payload contains future `exp` (unix timestamp), for example `{"exp": 4102444800}`.
- `INTENT_GUARD_APPROVAL_AUTH_TOKEN`: bearer token added to webhook approval requests.

## SDK usage (Python)

```python
from intent_guard import IntentGuardSDK

guard = IntentGuardSDK(
    policy_path="schema/policy.yaml",
    local_model="llama3.1:8b",
    task_context="Only modify UI components"
)

decision = guard.evaluate("write_file", {"path": "src/auth/config.py"})
print(decision.allowed, decision.reason)
```

## GuardDecision contract (stable)

`GuardDecision` now includes machine-readable metadata for enforcement and analytics:

- `decision_id` (UUID)
- `code`
- `severity`
- `policy_name`
- `policy_version`
- `rule_id`
- `timestamp` (UTC ISO-8601)
- `override` (`who`/`why`/`ttl`, when manually approved)
- `semantic_prompt_version` (when semantic checks are applied)

Backward compatibility:
- Existing fields `allowed`, `reason`, `requires_approval`, `semantic_score` are unchanged.
- New fields are always present with safe defaults, so existing consumers can ignore them.

## Semantic eval harness

IntentGuard ships a lightweight semantic eval harness used in tests to measure model behavior on known-safe and known-unsafe tool calls.

- Dataset fixtures: `tests/fixtures/semantic_eval_dataset.json`
- Replay verdicts: `tests/fixtures/semantic_eval_verdicts.json`
- Metrics computed: precision, recall, accuracy

This enables reproducible regression checks for semantic policy quality.

Versioning/migration strategy:
- Keep parsing logic tolerant of unknown fields.
- Use `policy_version` + `code` + `rule_id` for downstream contract evolution and dashboards.
- Prefer adding new fields over changing/removing existing field semantics.

## Usage examples with popular tools

### 1) Claude Code (MCP server proxy)

Configure the MCP server command to run through IntentGuard:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "python",
      "args": [
        "-m",
        "intent_guard.proxy",
        "--policy",
        "schema/policy.yaml",
        "--target",
        "npx @modelcontextprotocol/server-filesystem /path/to/repo",
        "--ask-approval"
      ],
      "env": {
        "INTENT_GUARD_TASK": "Refactor UI only; do not touch auth or database"
      }
    }
  }
}
```

### 2) Codex (MCP command wrapping)

For Codex setups that support MCP server command configuration, point the server command to IntentGuard first, then to your real MCP server as `--target`:

```bash
python -m intent_guard.proxy \
  --policy schema/policy.yaml \
  --target "npx @modelcontextprotocol/server-filesystem /path/to/repo" \
  --ask-approval
```

Use that command as the configured MCP server entry in your Codex environment.

### 3) LangSmith / LangChain workflows

Use IntentGuard before each tool execution and keep normal LangSmith tracing:

```python
from langsmith import traceable
from intent_guard import IntentGuardSDK

guard = IntentGuardSDK(
    policy_path="schema/policy.yaml",
    task_context="Only update docs and UI text"
)

@traceable(name="guarded_tool_call")
def guarded_call(tool_name: str, args: dict, tool_callable):
    decision = guard.evaluate(tool_name, args)
    if not decision.allowed:
        raise PermissionError(f"IntentGuard blocked: {decision.reason}")
    return tool_callable(**args)
```

This keeps execution decisions visible in traces while enforcing IntentGuard policy at runtime.

## Build and publish (pip / Artifactory)

Build source and wheel distributions:

```bash
python3 -m venv .venv
.venv/bin/pip install -U pip build twine
.venv/bin/python -m build
```

Publish to your Artifactory PyPI repository:

```bash
export TWINE_USERNAME="<artifactory-username>"
export TWINE_PASSWORD="<artifactory-password-or-token>"
.venv/bin/python -m twine upload \
  --repository-url "https://<artifactory-host>/artifactory/api/pypi/<pypi-repo>/local" \
  dist/*
```

## Integration testing and Docker

Current integration tests are in-process (`tests/test_integration_phases.py`) and do not require a database or cache service.
If a future change adds external DB/cache dependencies, run those services in Docker for tests (same pattern as `temp-noob/rule-engine`) so test setup remains reproducible.
