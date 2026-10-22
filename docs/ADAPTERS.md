# Framework Adapters

Vanzik ships Python adapters that wrap popular agent frameworks so every tool call, navigation, or MCP request passes through `/v1/check` before executing. All adapters live under `plugins/python/vanzik/adapters/` and are gated behind pip extras (`pip install vanzik[langchain]` etc.).

| Integration | Tier | Module / Binary | Extra | Doc |
|---|---|---|---|---|
| **MCP Gateway** | Hero (wire-level) | `vanzik-mcp-gateway` binary | n/a (Go binary) | [`MCP_GATEWAY.md`](MCP_GATEWAY.md), [`QUICKSTART_MCP.md`](QUICKSTART_MCP.md) |
| **LLM API Proxy** | Hero (wire-level) | `vanzik-llm-proxy` binary | n/a (Go binary) | [`LLM_API_PROXY.md`](LLM_API_PROXY.md), [`QUICKSTART_LLM_PROXY.md`](QUICKSTART_LLM_PROXY.md) |
| LangChain | Compatibility (SDK) | `vanzik.adapters.langchain` | `[langchain]` | this doc |
| CrewAI | Compatibility (SDK) | `vanzik.adapters.crewai` | `[crewai]` | this doc |
| OpenAI Agents SDK | Compatibility (SDK) | `vanzik.adapters.openai_agents` | `[openai-agents]` | this doc |
| browser-use | Compatibility (SDK) | `vanzik.adapters.browseruse` | `[browser-use]` | this doc |
| MCP (Python adapter) | Compatibility (SDK) | `vanzik.adapters.mcp` | `[mcp]` (or core for legacy installs) | this doc |

The MCP Gateway and the LLM API Proxy are the **hero** integration paths — they enforce at the wire by sitting between the agent and its tools / model API, with no opt-in required by the agent code. The Python adapters in this doc form the **compatibility tier** for direct callers (offline scripts, custom transports, advisory enforcement) — each one gates the modern API of its target framework, and the agent must call the wrapped object for the gate to fire.

## Compatibility Matrix

The version pins live in [`plugins/python/pyproject.toml`](../plugins/python/pyproject.toml) under `[project.optional-dependencies]`. The CI `integration-tests` job runs each adapter against the real upstream package (the newest release inside each pin) on every push and PR, and on a weekly cron (Monday 06:00 UTC), so a breaking upstream release surfaces before a customer hits it. Each leg runs the framework's `test_real_*` suite and its `test_at_*` suite (a real agent loop end to end); the langchain leg also drives the real `vanzik-llm-proxy` binary (`test_at_llm_proxy_e2e.py`), the `mcp` leg drives the Python MCP gateway adapter against a real stdio MCP server, and the `openai-agents` leg drives a real `Agent` + `Runner` loop with an offline fake model (no API key). The advisory `python-extras-all` job installs `.[all,dev]` into a fresh environment, runs `pip check`, and runs the whole Python suite, so an extras set that stops resolving — or resolves to an unsupported framework version — shows up.

| Vanzik | LangChain | CrewAI | browser-use | MCP | OpenAI Agents SDK |
|---|---|---|---|---|---|
| 2.0.x | `langchain >=0.3,<2.0`, `langchain-core >=0.3,<2.0` | `crewai >=1.0,<2.0` | `browser-use >=0.4,<1.0`, `playwright >=1.40` | `mcp >=0.9,<3.0` | `openai-agents >=0.3.3,<1.0` |
| 1.4.x | `langchain >=0.3,<2.0`, `langchain-core >=0.3,<2.0` | `crewai >=1.0,<2.0` | `browser-use >=0.4,<1.0`, `playwright >=1.40` | `mcp >=0.9,<3.0` | `openai-agents >=0.3.3,<1.0` |
| 1.2.x – 1.3.x | `langchain >=0.3,<2.0`, `langchain-core >=0.3,<2.0` | `crewai >=1.0,<2.0` | `browser-use >=0.4,<1.0`, `playwright >=1.40` | `mcp >=0.9,<3.0` | — |
| 0.5.x – 1.1.x | `langchain >=0.3,<2.0`, `langchain-core >=0.3,<2.0` | `crewai >=0.80,<2.0` | `browser-use >=0.4,<1.0`, `playwright >=1.40` | `mcp >=0.9,<2.0` | — |
| 0.4.x | `>=0.1` (no upper bound — silent rot) | `>=0.1` | `>=0.1` (`goto` only) | wire protocol `2024-11-05` | — |

The floors cover the API surface Vanzik's adapters were built and hardened against (LangChain 0.3+'s split `langchain-core` package, CrewAI 1.0+ — see below — and browser-use 0.4+'s stable Page surface). Each ceiling sits at the next upstream major, so a new major can't install until it has been verified. As of 2026-09-24, the newest LangChain (1.x), CrewAI (1.x), browser-use (0.x) and MCP (2.x) releases are inside their pins.

**`pip install vanzik[all]`** resolves, as of 2026-09-24, to crewai 1.15, browser-use 0.11, langchain 1.4, mcp 1.28 and pydantic 2.12, and `pip check` is clean. The newest browser-use (0.13) pins `mcp==2.1.1` and `pydantic>=2.13`, which conflict with crewai 1.x, so pip picks an older browser-use; every adapter suite passes on that set.

### Pinning rationale

Upper bounds exist because a bare `>=0.1` floor allows silent rot when frameworks rename methods or add new bypass paths. Specifically:

- **LangChain** moved from a single `langchain` package on 0.1 to a split `langchain-core` (Runnable protocol) + `langchain` (agents / chains) on 0.3. LangChain has since reached 1.x, which the `<2.0` ceiling already admits and CI installs today; 2.0 gets re-verified before the ceiling moves.
- **CrewAI** moved its `BaseTool` to inherit from `langchain_core.runnables.Runnable` around 0.80, exposing the modern `invoke` / `ainvoke` / `stream` / `batch` surface. The floor is **1.0**: on 0.19x a crew kickoff dispatches agent tool calls through a path the adapter does not wrap (the tool runs with no `/v1/check` call), so the adapter refuses CrewAI below 1.0 with an `ImportError` instead of returning tools that look gated but aren't.
- **browser-use** 0.4 is the first release where the `Browser` / `Page` API stabilised enough that we could write a strict allowlist against it. Earlier versions reshape the page proxy across minor releases.
- **MCP** Python SDK (`mcp` on PyPI): the ceiling is `<3.0`; the adapter's suite and the gateway end-to-end suite pass on mcp 2.2.0 (and 2.1.1). 1.x stays supported.
- **OpenAI Agents SDK** (`openai-agents` on PyPI, import name `agents`): the floor is **0.3.3**, the first release with tool input guardrails and `ToolContext.tool_arguments`; the adapter refuses older releases with an `ImportError`. The unit and integration suites pass on 0.3.3 and on 0.23.1 (the newest release when the adapter landed). The package is pre-1.0, so the ceiling follows the browser-use rule: `<1.0`, not the next minor. The adapter only touches `FunctionTool.on_invoke_tool` and the public guardrail API, and the weekly integration run catches a breaking 0.x minor.

### Bumping the upper bound

1. Locally: `pip install -e ".[<framework>,dev]"` against the new major.
2. Run `pytest -m integration tests/integration/test_real_<framework>.py -v`. All tests must pass.
3. Update the upper bound in `plugins/python/pyproject.toml`.
4. Update this table.
5. Check the framework's changelog for new method names — if the framework added a method that side-steps our gate (`Runnable.with_listeners` did this in `langchain-core` 0.3.x), extend the adapter's gated set BEFORE bumping the pin.

### Which integration-tests legs block CI

The LangChain, CrewAI, MCP and OpenAI Agents SDK legs are required: a red leg fails CI. The browser-use leg is advisory (`continue-on-error`) for two reasons. Its `playwright install` step downloads about 200 MB of Chromium from a CDN and is the known flake. And like every leg, it tests against live upstream releases, so a red browser-use leg usually means upstream drift, not a Vanzik regression. A red advisory leg still shows in the run, and the weekly cron run surfaces upstream breakage even when no PR is open.

Authors of adapter changes are still expected to drive the integration job to green locally before merging: from `plugins/python`, run `pytest -v -m integration tests/integration/test_real_<framework>.py` (the same invocation CI uses).

All adapters share the same philosophy: **decide via policy first, call the wrapped callable only if `ALLOW`**. On `DENY` or `REQUIRE_APPROVAL` the LangChain, CrewAI, OpenAI Agents SDK and browser-use adapters raise `PermissionError` (CrewAI and the OpenAI Agents SDK adapter raise its subclasses `VanzikDenied` and `VanzikApprovalRequired`). The one exception is LangChain's legacy `run` / `arun` entry points, which return a marker string for callers that depend on it. The MCP adapter returns a JSON-RPC result with `isError: true`.

---

## LangChain — `GuardedToolkit`

Source: `plugins/python/vanzik/adapters/langchain.py`.

### Usage

```python
from vanzik.adapters.langchain import GuardedToolkit
from langchain_core.tools import Tool

tools = [
    Tool(name="http_get", description="Fetch a URL", func=requests.get),
    Tool(name="file_read", description="Read a file from disk", func=open),
    Tool(name="shell", description="Run a shell command", func=os.system),
]

toolkit = GuardedToolkit(
    tools=tools,
    guard_url="http://localhost:8080",
    agent_id="my-langchain-agent",
    default_scope="shell",  # fallback when nothing else matches
)

agent = create_react_agent(llm, toolkit.tools, prompt)
```

`toolkit.tools` is a drop-in replacement for the original list — each tool is wrapped in a `GuardedTool` that preserves `.name`, `.description`, and `.args_schema`, and proxies every other attribute back to the original via `__getattr__`.

### Scope inference

LangChain tools have a free-form `name + description`. The toolkit runs two passes to decide the scope.

**Static inference (at construction)** scans `name + description` for keywords:

| Keyword group | Scope |
|---|---|
| `http`, `api`, `fetch`, `request`, `url`, `web` | `network` |
| `file`, `read`, `write`, `directory`, `path` | `filesystem` |
| `browser`, `navigate`, `click`, `page` | `browser` |
| `shell`, `command`, `exec`, `terminal`, `bash` | `shell` |
| none of the above | `default_scope` (default `shell`) |

**Runtime upgrade (at call)** looks at the tool input dict and promotes the scope if a more specific key appears:

- Any `url` or `domain` in the input → `network`.
- Any `path` or `file_path` in the input → `filesystem`.

The runtime upgrade always wins over the static guess. A tool statically classified as `shell` but called with `{"path": "/etc/passwd"}` will be checked against the `filesystem` rule set.

### Parameter extraction

`_infer_check_params` forwards to `/v1/check`:

- `command` ← `tool_input` (if string) or `tool_input["command"] / ["cmd"]`
- `url`, `domain` (derived via `urlparse`)
- `path` ← `tool_input["path"] / ["file_path"]`
- `action` inferred from the tool's own name: `read`/`get` → `read`; `write`/`save`/`create` → `write`; `delete`/`remove` → `delete`
- `session_id`, `est_cost` if present in the input (lets cost-scope policies work)

### Approval / deny behavior

The modern entry points (`invoke`, `ainvoke`, `_run`, `_arun`, `stream`, `astream`, `batch`, `abatch`) raise `PermissionError` on deny:

- `DENY`: `"[Vanzik] Tool '<name>' denied: <policy reason>"`
- `REQUIRE_APPROVAL`: `"[Vanzik] Tool '<name>' requires approval. Approve at: <url>\nReason: <reason>"`

A `batch` fails as a whole on the first denied input. The legacy `run` / `arun` entry points keep their older behavior and **return** a marker string instead of raising:

- `DENY`: `"[Vanzik] Action denied.\nReason: <policy reason>"`
- `REQUIRE_APPROVAL`: `"[Vanzik] Action requires approval. Approve at: <url>\nReason: <reason>"`

A raised `PermissionError` propagates out of the agent run unless your code catches it. LangChain's `handle_tool_error` does not apply: it only handles `ToolException`.

If you prefer to block until a human approves, call `guard.wait_for_approval(...)` in your own tool wrapper; the adapter does not do this automatically because it would turn every tool call into a potentially 5-minute blocking operation.

### Async tools

`arun` mirrors `run`. The policy check itself is synchronous (urllib), but the wrapped tool's `arun` is awaited. If your LangChain tool only has `run`, the wrapper still works — it only calls whichever method you invoke.

---

## CrewAI — `guard_crew_tools`

Source: `plugins/python/vanzik/adapters/crewai.py`.

### Usage

```python
from vanzik.adapters.crewai import guard_crew_tools
from crewai import Agent, Task

guarded = guard_crew_tools(
    tools=[my_search_tool, my_filesystem_tool],
    guard_url="http://localhost:8080",
    agent_id="crew-researcher",
    default_scope="shell",
)

agent = Agent(role="Researcher", tools=guarded, ...)
```

### Why `run` *and* `_run` are both gated

CrewAI's `BaseTool` exposes a public `run(...)` method for direct invocation and a protected `_run(...)` that its executor calls internally during agent orchestration (`invoke` and `to_structured_tool` reach it too). The wrapper gates **each** of them:

```python
def run(self, *args, **kwargs):
    # policy check, then self._tool.run(...)

def _run(self, *args, **kwargs):
    # policy check, then self._tool._run(...)
```

If we gated only `run`, a CrewAI agent orchestrating tools would bypass the policy by calling `_run` directly. Neither method calls the other, so each call is checked once. `run` forwards to the wrapped tool's own `run`, so CrewAI's usage accounting still runs on `ALLOW`, and the check fires first, so a denied call doesn't consume a usage slot.

### Scope inference differences from LangChain

CrewAI scope inference is the same two-pass approach (input keys → keyword inference → configured default) but with one behavioral difference: **the `shell` keyword group does not include CrewAI's default `"shell"` term**, because CrewAI tools' names rarely contain that literal token. Explicitly construct `GuardedCrewTool(tool, scope="shell")` if you want to pin a scope.

### Deny / approval behavior

Every entry point (`run`, `_run`, `invoke`, and their async counterparts) raises before the wrapped tool runs: `VanzikApprovalRequired` on `REQUIRE_APPROVAL` and `VanzikDenied` on `DENY`. Both subclass `PermissionError` and carry the `CheckResult` as `.result`. A denied call does not consume a CrewAI usage slot.

---

## OpenAI Agents SDK — `guard_tools`

Source: `plugins/python/vanzik/adapters/openai_agents.py`. Install with `pip install 'vanzik[openai-agents]'`.

### Usage

```python
from agents import Agent, Runner, function_tool
from vanzik import VanzikDenied, Guard
from vanzik.adapters.openai_agents import guard_tools

@function_tool
def run_shell(command: str) -> str:
    """Run a shell command."""
    ...

guard = Guard("http://localhost:8080", agent_id="ops-agent")
agent = Agent(name="ops", tools=guard_tools([run_shell], guard))

try:
    result = await Runner.run(agent, "clean up the build directory")
except VanzikDenied as e:
    print("blocked:", e.result.reason)
```

`guard_tool(tool, guard, scope=None)` gates one tool; `guard_tools(tools, guard, scope=None)` gates a list with one shared `Guard`. Each returns a copy of the `FunctionTool` with the same name, description and JSON schema; the caller's tool is not changed. The copy's `on_invoke_tool` runs `Guard.check` first and calls the original only on `ALLOW`.

Only function tools can be gated: anything `@function_tool` or `Agent.as_tool()` returns. Hosted tools such as `WebSearchTool` run on OpenAI's servers, so `guard_tool` raises `TypeError` for them instead of passing them through ungated. Tools that come from an agent's `mcp_servers` do not go through `tools`; gate those with [`vanzik-mcp-gateway`](MCP_GATEWAY.md).

### Scope inference

Pass `scope=` to fix the scope for every call. Otherwise it is inferred per call, in this order:

1. A `url` or `domain` argument → `network`.
2. A `path` or `file_path` argument → `filesystem`.
3. Keywords in the tool name and description, the same groups as CrewAI: `http`, `api`, `fetch`, `request`, `url`, `web` → `network`; `file`, `read`, `write`, `directory`, `path` → `filesystem`; `browser`, `navigate`, `click`, `page` → `browser`.
4. Otherwise `shell`.

### Parameter extraction

The SDK passes the model's arguments to `on_invoke_tool` as a JSON string. The adapter parses it and forwards the same fields as the other adapters: `command` (or `cmd`), `url` plus its `domain`, `path` (or `file_path`) plus an `action` inferred from the tool-name verb (`read_file` → `read`), `session_id` and `est_cost`.

If the arguments are not valid JSON, the raw string is checked as a `command`. The original string still goes to the tool, so the SDK's own validation rejects it after an `ALLOW`.

`guard_tool` projects the arguments onto the properties the tool's `params_json_schema` declares before extracting them (unless the schema allows additional properties). The SDK's params model drops undeclared keys, so the check sees exactly what the tool receives: a stray `path` cannot move a shell call to the `filesystem` scope.

If two names for one parameter are both present with different values (`{"command": "ls", "cmd": "rm -rf /"}`, or `path` and `file_path`), the call is denied without a server round-trip, since the adapter cannot know which one the tool reads. This applies to every adapter that uses the shared extraction (LangChain, CrewAI, MCP and both OpenAI Agents entry points).

### Approval / deny behavior

On `DENY` the adapter raises `VanzikDenied`, and on `REQUIRE_APPROVAL` it raises `VanzikApprovalRequired` (with `.approval_id` and `.approval_url`). Both are raised before the tool body runs. An unknown decision is treated as a deny.

What the model sees: nothing. The gate sits outside the tool's own error handling, so the SDK's `failure_error_function` never turns a deny into a tool output. That matters because the SDK's default handler answers the model with a generic "An error occurred while running the tool. Please try again." (from 0.23; earlier releases append the error text), which invites a retry. Instead the run ends and `Runner.run` (or the `stream_events()` loop of `Runner.run_streamed`) raises the exception to your code. The raised object also subclasses the SDK's `AgentsException`, which the runner re-raises as-is rather than wrapping it in `UserError`, so `except VanzikDenied` and `except PermissionError` both work.

Nested agents are the exception. If the guarded tools belong to an inner agent that an outer agent calls through `inner.as_tool()`, the deny still ends the inner run, but it is raised inside the outer agent's tool, and that tool's default `failure_error_function` turns it into a tool error. The outer run continues, and the outer model sees the SDK's generic error message (from 0.23 without the Vanzik reason; earlier releases append it). To end the outer run too, build the inner tool with `inner.as_tool(..., failure_error_function=None)` (on releases whose `as_tool` takes that argument); `Runner.run` on the outer agent then raises `VanzikDenied`. Either way the denied tool never runs.

If the model should see the reason and continue, add the tool input guardrail:

```python
from vanzik.adapters.openai_agents import vanzik_tool_guardrail

@function_tool(tool_input_guardrails=[vanzik_tool_guardrail(guard)])  # 0.7.0+
def run_shell(command: str) -> str:
    ...

# On 0.3.3 – 0.6.x, set the field instead:
# run_shell.tool_input_guardrails = [vanzik_tool_guardrail(guard)]
```

On `DENY` or `REQUIRE_APPROVAL` the guardrail rejects the call: the tool does not run, the model gets the Vanzik message (`[Vanzik] Action denied.` plus the reason, or the approval URL) as the tool result, and the run continues. With `raise_on_block=True` it trips instead and `Runner.run` raises `ToolInputGuardrailTripwireTriggered`; the guardrail result's `output_info` holds the `CheckResult`. The guardrail sees the tool name and arguments but not the description, so its scope inference skips the description keywords.

Guardrails only run inside the SDK runner; calling a tool's `on_invoke_tool` directly skips them. `guard_tool` is the gate that always fires. Using both on one tool checks every call twice.

### Async

The SDK runs tools on an asyncio event loop, and `Guard.check` is a blocking HTTP call. The adapter runs the check with `asyncio.to_thread`, so a slow check does not stall other tasks, and parallel tool calls are checked in parallel.

---

## browser-use — `GuardedBrowser` + `GuardedPage`

Source: `plugins/python/vanzik/adapters/browseruse.py`.

### Two integration styles

**1. Check-then-act.** Call a `check_*` method, inspect the result, then drive the browser yourself:

```python
from vanzik.adapters.browseruse import GuardedBrowser

browser = GuardedBrowser(guard_url="http://localhost:8080", agent_id="browse-bot")

nav = browser.check_navigation("https://example.com")
if nav.allowed:
    await page.goto("https://example.com")
elif nav.needs_approval:
    print(f"Awaiting approval: {nav.approval_url}")
else:
    print(f"Blocked: {nav.reason}")
```

**2. Wrap the page.** `wrap_page(page)` returns a `GuardedPage`. Each of its action methods checks policy first, raises `PermissionError` on deny/approval, and otherwise forwards to the real page:

```python
guarded_page = browser.wrap_page(page)
await guarded_page.goto("https://example.com")  # may raise PermissionError
```

`GuardedPage` gates these 14 methods:

| Methods | Scope sent | `action` sent |
|---|---|---|
| `goto` | `browser` | `goto` |
| `click`, `press`, `select_option`, `check`, `uncheck` | `browser` | the method name |
| `fill`, `type` | **`data`** | `form_input` (same payload as `check_form_input`, below) |
| `evaluate`, `evaluate_handle`, `add_init_script` | `browser` | the method name; the script is redacted, and replaced with `<redacted; len=N>` past 256 characters |
| `set_extra_http_headers` | `browser` | `set_headers`; only the header names are sent |
| `expose_function` | `browser` | `expose_function` |
| `route` | `network` | `route` |

Only the read-only attributes `url`, `title`, `content`, `viewport_size`, `is_closed`, `main_frame` and `context` pass through to the real page. Any other attribute raises `AttributeError` rather than reach the page ungated; to cover a new Page method, add a gated wrapper to `GuardedPage`. `guarded_page.frame(...)` and `guarded_page.frames` return `GuardedFrame` objects, which gate `goto`, `click`, `fill`, `type` and `evaluate` the same way (the `action` gets a `frame.` prefix, except `fill` / `type`, which send `form_input` with `meta.frame: "true"`).

### Methods

| Method | Scope sent | What it checks |
|---|---|---|
| `check_navigation(url)` | `browser` | Navigation target + extracted `domain`. |
| `check_action(action, target, meta=...)` | `browser` | Clicks, screenshots, etc. Sends `command: "<action> <target>"`. |
| `check_form_input(url, field_name, value)` | **`data`** | Typing into a form field. Uses the `data` scope so policy can distinguish content-egress from navigation. |

`check_form_input`, and the `fill` / `type` methods of `GuardedPage` and `GuardedFrame`, use the `data` scope, which is designed for preventing PII/credential leakage into web forms. They send `action: "form_input"`, the page `url` and its `domain`, `meta.field` = the field name (the selector, for `fill` / `type`), and `command` = the value, redacted: a value longer than 256 characters becomes `<redacted; len=N>`, and a shorter one has the standard secret patterns (Bearer tokens, AWS keys, `secret=…` pairs, `ghp_…`, `xox?-…`) scrubbed. A `data`-scope rule can match on that `command` (for example `pattern: "*ssn:*"`) or on `domain`. The redacted value is what the audit log records. See [Data scope](POLICY_REFERENCE.md#data-scope) for the request fields.

### Why `goto` raises instead of returning a string

Browser navigation is side-effectful with no natural "return text to the LLM" slot — if `goto` silently no-op'd on deny, the downstream `page.content()` would run against a stale page. Raising `PermissionError` forces the agent framework's retry/fail path.

---

## MCP — `GuardedMCPServer`

Source: `plugins/python/vanzik/adapters/mcp.py`.

### What MCP is

The [Model Context Protocol](https://modelcontextprotocol.io) is a JSON-RPC over stdio protocol that Claude Desktop, Cursor, and similar clients use to talk to tool servers. `GuardedMCPServer` implements the server side: it reads JSON-RPC requests on stdin, routes them, and writes responses on stdout. Every `tools/call` request is routed through Vanzik before the real handler runs.

### Supported methods

| Method | Behavior |
|---|---|
| `initialize` | Returns pinned `protocolVersion: "2024-11-05"` + `serverInfo` + `capabilities.tools`. |
| `notifications/initialized` | Acknowledged (no response body; JSON-RPC notification). |
| `tools/list` | Returns every registered tool's `name`, `description`, `inputSchema`. |
| `tools/call` | Policy check → handler → content block. |
| any other | `{ "error": { "code": -32601, "message": "Unknown method: ..." } }` |

### Protocol version pinning

`MCP_PROTOCOL_VERSION = "2024-11-05"`. If a client requests a different version in `initialize.params.protocolVersion`, the server **logs a WARN to stderr** and still responds with the pinned version. stdout is reserved for JSON-RPC on the stdio transport, so the warning must not go to stdout.

The Python adapter does not negotiate protocol versions — for full version negotiation, use the `vanzik-mcp-gateway` Go binary instead (see [`docs/MCP_GATEWAY.md`](MCP_GATEWAY.md)). If you see the warn repeatedly with the Python adapter, downgrade the client to `2024-11-05`.

### Registering tools

```python
from vanzik.adapters.mcp import GuardedMCPServer

server = GuardedMCPServer(
    guard_url="http://localhost:8080",
    agent_id="mcp-claude-desktop",
)

server.add_tool(
    name="read_file",
    description="Read a file from disk",
    input_schema={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
    scope="filesystem",
    handler=lambda path: open(path).read(),
)

server.run()  # blocks, reads stdin forever
```

### Scope inference on `tools/call`

The per-tool `scope` set at `add_tool` time is the default. The adapter upgrades to a more specific scope based on the arguments:

- `arguments["url"]` or `arguments["domain"]` → `network` (extracts `domain` via `urlparse`).
- `arguments["path"]` or `arguments["file_path"]` → `filesystem`.

Parameter mapping is the same as the other adapters: `command`/`cmd`, `url`, `path`/`file_path`, plus `session_id` / `est_cost` for cost scope. If the tool's scope is `shell` and no `command`/`cmd` is present, the adapter synthesizes one: `f"{tool.name} {json.dumps(arguments)}"` — so a policy can still match on the tool-name pattern even when the tool is argument-driven.

### Error redaction

If the wrapped handler raises, the adapter returns:

```
Error (<ExceptionType>): <redacted message>
```

The redaction regex list is `pkg/notify/notify.go`'s `DefaultRedactor`, pattern for pattern (a test checks they're identical) — Bearer tokens, AWS `AKIA...`, Slack tokens (`xox[baprs]-...`), `key=value` for `secret/token/password/api_key`, and from 1.2.0 `sk-...` LLM keys, Google `AIza...` keys, GitHub `gh[pousr]_...` and `github_pat_...` tokens, JWTs, PEM private keys and `Authorization` / `x-api-key` header values. The raw, unredacted exception is written to stderr for operator visibility; only the redacted form crosses the JSON-RPC boundary back to the MCP client.

This matters because the MCP client is arbitrary (Claude Desktop, Cursor, a script). A naive `str(e)` leak of a bearer token would cross a trust boundary.

### Running as a standalone MCP server

The module entry point has two modes — gateway and empty-server.

#### Gateway mode (preferred, v0.5+)

`--upstream "<command>"` spawns the given downstream MCP server, brokers JSON-RPC frames between the client (Claude Desktop, Cursor, …) and the upstream, and gates every `tools/call` through Vanzik:

```bash
python -m vanzik.adapters.mcp \
  --guard-url http://localhost:8080 \
  --upstream "npx -y @modelcontextprotocol/server-filesystem /tmp"
```

Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "vanzik-fs": {
      "command": "python",
      "args": [
        "-m", "vanzik.adapters.mcp",
        "--guard-url", "http://localhost:8080",
        "--upstream", "npx -y @modelcontextprotocol/server-filesystem /tmp"
      ]
    }
  }
}
```

The Python gateway is a compatibility-tier alternative to the
production `vanzik-mcp-gateway` Go binary (see
[`docs/MCP_GATEWAY.md`](MCP_GATEWAY.md)). Limitations vs the Go
binary:

- Single upstream only — no capability merging.
- No tool-name namespacing / prefixing.
- Server-initiated notifications (`notifications/tools/list_changed`) are not relayed.
- Only `tools/*` is gated; `prompts/*` and `resources/*` are not.

#### Empty-server mode (back-compat)

Running the entry point without `--upstream` starts a server that registers no tools. Useful for programmatic embedding via `GuardedMCPServer.add_tool(...)` in custom code; useless when wired to Claude Desktop verbatim. The adapter logs a stderr WARN at startup so an operator following the docs literally sees the misconfiguration immediately:

```bash
python -m vanzik.adapters.mcp --guard-url http://localhost:8080
# WARN vanzik.mcp: starting with NO tools registered. Pass --upstream …
```

For programmatic use you typically don't invoke `python -m`; you import the class directly (see "Registering tools" above).

---

## Common patterns across adapters

### Configuring the underlying `Guard`

All adapters accept either `guard=<Guard instance>` (re-use) or `guard_url=... + agent_id=...` (construct), except the OpenAI Agents SDK adapter, which takes a `Guard` only. Share one `Guard` across adapters in the same process so env-fallback behavior is consistent:

```python
from vanzik import Guard
from vanzik.adapters.langchain import GuardedToolkit
from vanzik.adapters.crewai import guard_crew_tools

shared = Guard("http://localhost:8080", agent_id="multi-framework-agent", api_key="…")
langchain_tools = GuardedToolkit(my_lc_tools, ...).tools  # or inject shared via custom construction
crew_tools = guard_crew_tools(my_crew_tools, ...)
```

### Fail-closed by default

Each adapter delegates to `Guard.check(...)`. The underlying `Guard` is fail-closed unless constructed with `fail_mode="allow"`. If your proxy is down in development, tools will return deny markers — set `fail_mode="allow"` or run the proxy locally.

### Cost scope hints

Every adapter forwards `session_id` and `est_cost` from the tool input to the policy check. If your tools carry those keys (even nominally), cost-scope rules work across frameworks without extra wiring.

### What the adapters do NOT do

- They do **not** rate-limit locally. Rate limiting lives in the proxy.
- They do **not** block on `REQUIRE_APPROVAL`. Call `guard.wait_for_approval(...)` yourself if you want blocking.
- They do **not** modify tool input or output. Only the decision gates execution.
- They do **not** attempt schema validation of `arguments` against `inputSchema` (MCP) — that is the upstream protocol's job.

---

## Related docs

- [`docs/SDK_PYTHON.md`](SDK_PYTHON.md) — underlying `Guard` client reference.
- [`docs/POLICY_REFERENCE.md`](POLICY_REFERENCE.md) — scopes each adapter emits to (`shell`, `filesystem`, `network`, `browser`, `data`, `cost`).
- [`docs/TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — adapter-specific failure symptoms.
- `plugins/python/vanzik/adapters/*.py` — source of truth; all behavior documented above is code-backed.
