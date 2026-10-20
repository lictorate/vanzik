# Vanzik Python SDK

Lightweight Python client for [Vanzik](https://github.com/lictorate/vanzik) — the firewall for AI agents.

- **Zero runtime dependencies** for the core SDK (stdlib `urllib`).
- **Fail-closed by default** — if the proxy is unreachable, `check()` returns `DENY`.
- **Framework adapters** for LangChain, CrewAI, browser-use, MCP, and the OpenAI Agents SDK, gated behind optional extras.

> **Deep reference:** [`docs/SDK_PYTHON.md`](../../docs/SDK_PYTHON.md) — full API, exception hierarchy, fail-mode details, adapter internals.

## Install

```bash
pip install vanzik

# With framework adapters
pip install vanzik[langchain]
pip install vanzik[crewai]
pip install vanzik[browser-use]
pip install vanzik[mcp]
pip install 'vanzik[openai-agents]'
pip install vanzik[all]
```

The package and the import are both `vanzik`.

## Quick start

```python
from vanzik import Guard

guard = Guard(
    base_url="http://localhost:8080",   # or set VANZIK_URL
    agent_id="my-agent",
    api_key="…",                        # or set VANZIK_API_KEY (needed for approve/deny/status)
)

result = guard.check("shell", command="rm -rf ./old_data")

if result.allowed:
    execute(command)
elif result.needs_approval:
    print(f"Approve at: {result.approval_url}")
    # Block until a human resolves it, or 5 min deadline, whichever first
    final = guard.wait_for_approval(result.approval_id, timeout=300)
    if final.allowed:
        # Replay the approval: consumes the one-shot ALLOW, reserves cost,
        # and audits the execution. The status poll alone spends nothing.
        replay = guard.check("shell", command=command, approval_id=result.approval_id)
        if replay.allowed:
            execute(command)
else:
    print(f"Blocked: {result.reason}")
```

### Environment variables

| Var | Default | Used by |
|---|---|---|
| `VANZIK_URL` | `http://localhost:8080` | `Guard(base_url="")` fallback |
| `VANZIK_API_KEY` | *(empty)* | `Guard(api_key="")` fallback; sent as `Authorization: Bearer <key>` on `/v1/approve`, `/v1/deny`, `/v1/status` |
| `VANZIK_TENANT_ID` | *(empty)* | `Guard(tenant_id=None)` fallback; a value other than `local` routes calls to `/v1/t/<tenant>/…` |

### Fail mode

```python
# Default: fail closed. Proxy unreachable → CheckResult(decision="DENY", reason="Vanzik unreachable (deny): …")
guard = Guard("http://localhost:8080")

# Opt in to fail open. Proxy unreachable → CheckResult(decision="ALLOW", reason="Vanzik unreachable (allow): …")
# Use only when your threat model treats Vanzik as advisory.
guard = Guard("http://localhost:8080", fail_mode="allow")
```

Fail mode applies to transport failures — `urllib.error.URLError` (connection refused / DNS / SSL, and HTTP error statuses), `OSError` (post-connect timeouts and resets), `json.JSONDecodeError` (garbage response body) — and to responses that aren't a valid decision (a non-JSON `Content-Type`, or a body without `decision`).

## The `@guarded` decorator

```python
from vanzik import Guard, guarded, VanzikDenied, VanzikApprovalRequired

guard = Guard("http://localhost:8080", agent_id="my-agent")

@guarded("shell", guard=guard)
def run_command(cmd: str):
    os.system(cmd)

try:
    run_command("ls")
    run_command("rm -rf /")        # raises VanzikDenied
except VanzikDenied as e:
    log(f"blocked: {e.result.reason}")
```

On `REQUIRE_APPROVAL` the decorator raises `VanzikApprovalRequired` immediately. To block until a human resolves it, opt in:

```python
@guarded("cost", guard=guard, wait_for_approval=True, approval_timeout=300)
def expensive_call(prompt: str): ...
```

All Vanzik exceptions (`VanzikDenied`, `VanzikApprovalRequired`, `VanzikApprovalTimeout`, `VanzikAuthError`) extend `PermissionError`, so existing `except PermissionError:` handlers keep working unchanged.

## Framework adapters

### LangChain

```python
from vanzik.adapters.langchain import GuardedToolkit

toolkit = GuardedToolkit(
    tools=my_tools,
    guard_url="http://localhost:8080",
    agent_id="langchain-agent",
)
agent = create_react_agent(llm, toolkit.tools, prompt)
```

Scope is inferred from each tool's name/description (`http/api`→network, `file/path`→filesystem, `browser`→browser, `shell`→shell) and upgraded at call time if the input dict contains `url`, `domain`, or `path` keys.

### CrewAI

```python
from vanzik.adapters.crewai import guard_crew_tools

guarded_tools = guard_crew_tools(
    tools=my_crew_tools,
    guard_url="http://localhost:8080",
    agent_id="crew-agent",
)
```

Hooks both `run` and `_run` (CrewAI calls `_run` internally).

### browser-use

```python
from vanzik.adapters.browseruse import GuardedBrowser

browser = GuardedBrowser(guard_url="http://localhost:8080")

if browser.check_navigation("https://example.com").allowed:
    await page.goto("https://example.com")

# Or wrap the page directly so goto() enforces policy for you:
guarded_page = browser.wrap_page(page)
await guarded_page.goto("https://example.com")   # raises PermissionError on deny/approval
```

### MCP

```python
from vanzik.adapters.mcp import GuardedMCPServer

server = GuardedMCPServer(guard_url="http://localhost:8080")
server.add_tool("my_tool", "Description", handler=my_handler)
server.run()   # stdio JSON-RPC MCP server; pins MCP_PROTOCOL_VERSION
```

Or as a drop-in stdio server:

```bash
python -m vanzik.adapters.mcp --guard-url http://localhost:8080
```

### OpenAI Agents SDK

```python
from agents import Agent, Runner, function_tool
from vanzik import VanzikDenied, Guard
from vanzik.adapters.openai_agents import guard_tools

@function_tool
def run_shell(command: str) -> str:
    ...

guard = Guard("http://localhost:8080", agent_id="ops-agent")
agent = Agent(name="ops", tools=guard_tools([run_shell], guard))

try:
    result = await Runner.run(agent, "clean up the build directory")
except VanzikDenied as e:
    print("blocked:", e.result.reason)
```

`guard_tools` returns gated copies of the `FunctionTool`s; DENY and REQUIRE_APPROVAL raise out of `Runner.run` before the tool runs. To let the model see the reason and continue instead, attach `vanzik_tool_guardrail(guard)` as a tool input guardrail. Hosted tools (`WebSearchTool`, ...) cannot be gated. Runnable example: [`examples/openai-agents-config.py`](../../examples/openai-agents-config.py).

## API reference (summary)

### `Guard(base_url="", agent_id="", timeout=5, api_key="", fail_mode="deny", tenant_id=None)`

| Method | Behavior |
|---|---|
| `check(scope, *, action, command, path, domain, url, session_id, est_cost, meta, approval_id)` | POST `/v1/check` (`approval_id` replays a resolved approval — see the quick start). Returns `CheckResult`. Transport failure → fail-closed `DENY` (or `ALLOW` if `fail_mode="allow"`). |
| `approve(id)` / `deny(id)` | POST `/v1/approve/{id}` / `/v1/deny/{id}`. Returns `bool` success. Sends Bearer if `api_key` set. |
| `wait_for_approval(id, timeout=300, poll_interval=2)` | Polls `GET /v1/status/{id}` until `resolved` or deadline. Timeout → `CheckResult(DENY, "Approval timed out")`. |

### `CheckResult`

Fields: `decision`, `reason`, `matched_rule`, `approval_id`, `approval_url`. Properties: `.allowed`, `.denied`, `.needs_approval`.

### Exception hierarchy (all extend `PermissionError`)

- `VanzikError` — base; carries `.result: CheckResult`.
- `VanzikDenied` — policy said DENY.
- `VanzikApprovalRequired` — policy said REQUIRE_APPROVAL and the decorator was not configured to wait. Carries `.approval_id`, `.approval_url`.
- `VanzikApprovalTimeout` — `wait_for_approval` deadline elapsed. Carries `.approval_id`.
- `VanzikAuthError` — a `wait_for_approval` status poll got `401`/`403` (API key missing or wrong). Carries `.status`.

## License

Apache 2.0
