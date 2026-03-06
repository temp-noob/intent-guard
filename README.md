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
3. **Llama Guard Integration via Ollama (Phase 3)**  
   `intent_guard/sdk/providers.py` implements `OllamaProvider`, calling `POST /api/generate` and parsing `SAFE`/`UNSAFE` + score.
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
  guardrail_model: llama-guard-3-8b
  critical_intent_threshold: 0.85
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
  --model llama-guard3 \
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

### CI break-glass options

- `INTENT_GUARD_BREAK_GLASS_TOKEN`: if set, flagged calls are auto-approved with override metadata.
- `INTENT_GUARD_BREAK_GLASS_SIGNED_TOKEN` + `INTENT_GUARD_BREAK_GLASS_SIGNING_KEY`: optional HMAC-signed break-glass token for CI. Token format is `<base64url(json payload)>.<base64url(signature)>` where signature is `HMAC-SHA256(payload_part, signing_key)` and payload contains future `exp` (unix timestamp).
- `INTENT_GUARD_APPROVAL_AUTH_TOKEN`: bearer token added to webhook approval requests.

## SDK usage (Python)

```python
from intent_guard import IntentGuardSDK

guard = IntentGuardSDK(
    policy_path="schema/policy.yaml",
    local_model="llama-guard3",
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

Backward compatibility:
- Existing fields `allowed`, `reason`, `requires_approval`, `semantic_score` are unchanged.
- New fields are always present with safe defaults, so existing consumers can ignore them.

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
