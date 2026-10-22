"""The :class:`Guard` HTTP client, :class:`CheckResult`, the typed
exceptions and the wire-level constants. Import them from the ``vanzik``
package root; this module is an implementation detail.
"""

import json
import logging
import os
import random
import time
from dataclasses import dataclass
from typing import Optional
from urllib import request, error
from urllib.parse import quote as urlquote


# Warns about transport oddities (bad status, content type, body) that the
# SDK answered via fail_mode. Add a NullHandler to silence it.
log = logging.getLogger("vanzik")

# --- Defaults and constants ---
DEFAULT_BASE_URL = "http://localhost:8080"
DEFAULT_TIMEOUT = 5           # seconds, for individual HTTP calls
DEFAULT_APPROVAL_TIMEOUT = 300  # seconds, for wait_for_approval
DEFAULT_POLL_INTERVAL = 2       # seconds

# Decision values (must match the Go backend)
DECISION_ALLOW = "ALLOW"
DECISION_DENY = "DENY"
DECISION_REQUIRE_APPROVAL = "REQUIRE_APPROVAL"

# Endpoint suffixes; Guard._url prepends "/v1" or "/v1/t/<tenant>".
ENDPOINT_CHECK = "/check"
ENDPOINT_APPROVE = "/approve/"
ENDPOINT_DENY = "/deny/"
ENDPOINT_STATUS = "/status/"

# The single-tenant alias: passing "local" equals omitting tenant_id. Any
# other value selects the /v1/t/{tenant_id}/... URL family.
LOCAL_TENANT_ID = "local"

# Guard(fail_mode=...) when the proxy is unreachable: "deny" (default) fails
# closed; "allow" fails open, an explicit opt-in for best-effort setups.
FAIL_MODE_DENY = "deny"
FAIL_MODE_ALLOW = "allow"
_VALID_FAIL_MODES = (FAIL_MODE_DENY, FAIL_MODE_ALLOW)

_MIGRATION_URL = "https://github.com/lictorate/vanzik/blob/master/docs/MIGRATION.md#v1x-to-v20"


def _from_env(name: str, default: str = "") -> str:
    """Return ``VANZIK_<name>``, or ``default`` when it is unset or empty.

    ``AGENTGUARD_<name>`` (the variable's name before Vanzik 2.0) is never
    read. When it is set and ``VANZIK_<name>`` is not, this raises
    ``ValueError`` instead of falling back: a client that ignored it would
    send no API key, or check calls against another server or tenant's
    policy, without saying so.
    """
    value = os.environ.get("VANZIK_" + name, "")
    if value:
        return value
    if os.environ.get("AGENTGUARD_" + name):
        raise ValueError(
            f"AGENTGUARD_{name} is set, but Vanzik reads VANZIK_{name}: "
            f"rename the variable (see {_MIGRATION_URL})"
        )
    return default


@dataclass
class CheckResult:
    """Result of a policy check."""
    decision: str
    reason: str
    matched_rule: str = ""
    approval_id: str = ""
    approval_url: str = ""

    @property
    def allowed(self) -> bool:
        return self.decision == DECISION_ALLOW

    @property
    def denied(self) -> bool:
        return self.decision == DECISION_DENY

    @property
    def needs_approval(self) -> bool:
        return self.decision == DECISION_REQUIRE_APPROVAL


# --- Typed exceptions raised by the @guarded decorator ---
#
# All extend PermissionError, so ``except PermissionError`` still catches
# them; the subclasses carry structured fields (result, approval_id,
# approval_url).

class VanzikError(PermissionError):
    """Base class for Vanzik-raised permission failures.

    Carries the originating :class:`CheckResult` (if any) so callers can
    inspect the decision, matched rule, and approval metadata without
    re-running the check. Messages preserve a stable string format so
    existing regex/text matchers continue to work.
    """

    def __init__(self, message: str, result: Optional[CheckResult] = None):
        super().__init__(message)
        self.result = result


class VanzikDenied(VanzikError):
    """Raised when the policy decision was DENY."""


class VanzikApprovalRequired(VanzikError):
    """Raised when the policy decision was REQUIRE_APPROVAL and the
    decorator was not configured to wait.
    """

    def __init__(
        self,
        message: str,
        result: Optional[CheckResult] = None,
        approval_id: str = "",
        approval_url: str = "",
    ):
        super().__init__(message, result)
        self.approval_id = approval_id
        self.approval_url = approval_url


class VanzikApprovalTimeout(VanzikError):
    """Raised when wait_for_approval was requested but the approval did
    not resolve before the deadline. The underlying ``result`` is the
    synthetic DENY/"Approval timed out" produced by :meth:`Guard.wait_for_approval`.
    """

    def __init__(
        self,
        message: str,
        result: Optional[CheckResult] = None,
        approval_id: str = "",
    ):
        super().__init__(message, result)
        self.approval_id = approval_id


class VanzikAuthError(VanzikError):
    """Raised when the Vanzik server returned 401 or 403 from an
    auth-gated endpoint (``/v1/approve``, ``/v1/deny``, ``/v1/status``,
    ``/v1/audit``).

    Distinguishes a wrong or expired API key from an approval timeout.
    """

    def __init__(
        self,
        message: str,
        status: int = 0,
        result: Optional[CheckResult] = None,
    ):
        super().__init__(message, result)
        self.status = status


# Back-compat alias; ``except VanzikApprovalTimeout:`` matches it too.
VanzikTimeoutError = VanzikApprovalTimeout


class Guard:
    """Client for the Vanzik server — the SDK enforcement layer.

    Call ``guard.check(scope, ...)`` before every gated action, or use the
    ``@guarded`` decorator / framework adapters in ``vanzik.adapters``
    for higher-level integration. For wire-level enforcement that needs no
    agent code change, see the ``vanzik-mcp-gateway`` and
    ``vanzik-llm-proxy`` binaries.
    """

    def __init__(
        self,
        base_url: str = "",
        agent_id: str = "",
        timeout: int = DEFAULT_TIMEOUT,
        api_key: str = "",
        fail_mode: str = FAIL_MODE_DENY,
        tenant_id: Optional[str] = None,
        parent_session_id: Optional[str] = None,
    ):
        """Construct a Guard client.

        Args:
            base_url: Proxy URL. Falls back to VANZIK_URL or the
                package default.
            agent_id: Stable identifier sent with every check.
            timeout: HTTP timeout in seconds for individual calls.
            api_key: Bearer token for /v1/approve, /v1/deny, /v1/status.
                Falls back to VANZIK_API_KEY.
            fail_mode: Behavior when the proxy is unreachable. "deny"
                (the default) returns a DENY result so the agent fails
                closed. "allow" returns an ALLOW result — use only when
                the threat model treats Vanzik as best-effort and
                the caller accepts the safety trade-off. An invalid
                value raises ValueError at construction.
            tenant_id: Optional tenant identifier. When set to a
                non-empty value other than ``"local"``, every HTTP call is
                routed through the tenant-aware ``/v1/t/{tenant_id}/...``
                URL family instead of the legacy ``/v1/...`` path.
                ``None`` or ``"local"`` selects the legacy URLs. Falls
                back to ``VANZIK_TENANT_ID``. The bundled
                FilePolicyProvider only recognises ``"local"``;
                multi-tenant providers can register others.
            parent_session_id: Optional. The session that started this
                agent's sessions, e.g. the orchestrator's session for a
                sub-agent. Sent as ``parent_session_id`` on every check
                (a per-call ``parent_session_id`` wins). Policy ignores
                it; the audit log records it so ``GET /v1/sessions`` can
                link parent and child sessions.
        """
        if fail_mode not in _VALID_FAIL_MODES:
            raise ValueError(
                f"fail_mode must be one of {_VALID_FAIL_MODES!r}, got {fail_mode!r}"
            )
        self.base_url = (base_url or _from_env("URL", DEFAULT_BASE_URL)).rstrip("/")
        self.agent_id = agent_id
        self.timeout = timeout
        self.api_key = api_key or _from_env("API_KEY")
        self.fail_mode = fail_mode
        # Explicit kwarg, then VANZIK_TENANT_ID. An explicit "" skips the env
        # lookup, so scoped tests can ignore a stray variable.
        if tenant_id is None:
            tenant_id = _from_env("TENANT_ID")
        self.tenant_id = tenant_id
        self.parent_session_id = parent_session_id or ""

    def _url(self, suffix: str) -> str:
        """Build the absolute URL for the given /v1 suffix.

        ``suffix`` is the path *after* ``/v1``, e.g. ``"/check"``,
        ``"/approve/ap_abc"``, ``"/audit"``. Tenant resolution:

        - tenant_id is unset, empty, or the literal ``"local"``:
          legacy URL family ``{base_url}/v1{suffix}``.
        - tenant_id is anything else: ``{base_url}/v1/t/{tenant_id}{suffix}``,
          with ``tenant_id`` URL-quoted via ``urllib.parse.quote(safe="")``
          so values containing ``/`` (or other reserved characters) are
          escaped rather than allowed to break the path layout.
        """
        if self.tenant_id and self.tenant_id != LOCAL_TENANT_ID:
            return f"{self.base_url}/v1/t/{urlquote(self.tenant_id, safe='')}{suffix}"
        return f"{self.base_url}/v1{suffix}"

    def check(
        self,
        scope: str,
        *,
        action: str = "",
        command: str = "",
        path: str = "",
        domain: str = "",
        url: str = "",
        session_id: str = "",
        est_cost: float = 0.0,
        meta: Optional[dict] = None,
        approval_id: str = "",
        parent_session_id: str = "",
    ) -> CheckResult:
        """Check an action against the policy.

        Args:
            scope: The rule scope (filesystem, shell, network, browser, cost, data)
            action: Action type (read, write, delete) — used with filesystem scope
            command: Shell command string — used with shell scope
            path: File path — used with filesystem scope
            domain: Target domain — used with network/browser scope
            url: Full URL — used with network scope
            session_id: Session identifier for session-level cost tracking
            est_cost: Estimated cost of this action in USD (for cost scope)
            meta: Additional metadata
            approval_id: Replay of a previously issued approval. Set it on
                the re-check after :meth:`wait_for_approval` resolved ALLOW,
                with the same scope and fields as the original request: the
                server then consumes the one-shot approval, enforces
                ``--approval-validity``, reserves cost for cost-scoped
                actions, and audits the execution as ``allow:approved``.
                A refused replay (consumed or expired) comes back as a fresh
                ``REQUIRE_APPROVAL`` under a new id. Omitted when empty.
            parent_session_id: The session that started ``session_id``.
                Defaults to the Guard's ``parent_session_id``. Recorded in
                the audit log, not used by policy. Omitted when empty.

        Returns:
            CheckResult with the policy decision
        """
        payload = {
            "scope": scope,
            "agent_id": self.agent_id,
        }
        if action:
            payload["action"] = action
        if command:
            payload["command"] = command
        if path:
            payload["path"] = path
        if domain:
            payload["domain"] = domain
        if url:
            payload["url"] = url
        if session_id:
            payload["session_id"] = session_id
        if est_cost:
            payload["est_cost"] = est_cost
        if meta:
            payload["meta"] = meta
        if approval_id:
            payload["approval_id"] = approval_id
        parent = parent_session_id or self.parent_session_id
        if parent:
            payload["parent_session_id"] = parent

        data = json.dumps(payload).encode("utf-8")
        req = request.Request(
            self._url(ENDPOINT_CHECK),
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with request.urlopen(req, timeout=self.timeout) as resp:
                # Positively assert 2xx, an application/json Content-Type
                # and a dict body with `decision`: a misconfigured reverse
                # proxy can return 200 with a non-JSON body that parses.
                # Any failure logs a warning and returns the fail_mode
                # result instead of raising. Minimal test fakes without a
                # status or headers attribute skip those two checks.
                status_attr = getattr(resp, "status", None)
                if status_attr is None and hasattr(resp, "getcode"):
                    try:
                        status_attr = resp.getcode()
                    except Exception:  # noqa: BLE001
                        status_attr = None
                if status_attr is not None and (status_attr < 200 or status_attr >= 300):
                    log.warning(
                        "vanzik: /v1/check returned non-2xx status=%s; "
                        "applying fail_mode=%s", status_attr, self.fail_mode,
                    )
                    return self._failmode_result(
                        f"Vanzik returned status {status_attr}"
                    )

                hdrs = getattr(resp, "headers", None)
                if hdrs is not None:
                    try:
                        ctype = (hdrs.get("Content-Type") or "").lower()
                    except Exception:  # noqa: BLE001
                        ctype = ""
                    if ctype and not ctype.startswith("application/json"):
                        log.warning(
                            "vanzik: /v1/check returned unexpected Content-Type "
                            "%r; applying fail_mode=%s", ctype, self.fail_mode,
                        )
                        return self._failmode_result(
                            f"Vanzik returned unexpected content-type {ctype!r}"
                        )

                body = json.loads(resp.read())
                if not isinstance(body, dict) or "decision" not in body:
                    log.warning(
                        "vanzik: /v1/check returned malformed body "
                        "(missing 'decision'); applying fail_mode=%s",
                        self.fail_mode,
                    )
                    return self._failmode_result(
                        "Vanzik returned malformed response body"
                    )
                return CheckResult(
                    decision=body.get("decision", DECISION_DENY),
                    reason=body.get("reason", ""),
                    matched_rule=body.get("matched_rule", ""),
                    approval_id=body.get("approval_id", ""),
                    approval_url=body.get("approval_url", ""),
                )
        except (error.URLError, OSError, json.JSONDecodeError) as e:
            # Transport failure, resolved by fail_mode. URLError covers
            # connect-phase failures; OSError covers post-connect ones from
            # resp.read() (ConnectionResetError, BrokenPipeError,
            # socket.timeout), which are not URLErrors and would otherwise
            # kill threaded callers such as the MCP adapter's workers; a
            # truncated or garbage body (JSONDecodeError) counts as
            # unreachable too.
            return self._failmode_result(
                f"Vanzik unreachable ({self.fail_mode}): {e}"
            )

    def _failmode_result(self, reason: str) -> CheckResult:
        """Build a CheckResult honoring ``self.fail_mode``."""
        decision = DECISION_ALLOW if self.fail_mode == FAIL_MODE_ALLOW else DECISION_DENY
        return CheckResult(decision=decision, reason=reason)

    def _auth_headers(self) -> dict:
        """Return Authorization header if api_key is set."""
        if self.api_key:
            return {"Authorization": f"Bearer {self.api_key}"}
        return {}

    def approve(self, approval_id: str) -> bool:
        """Approve a pending action."""
        req = request.Request(
            self._url(f"{ENDPOINT_APPROVE}{approval_id}"),
            headers=self._auth_headers(),
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout):
                return True
        except error.URLError:
            return False

    def deny(self, approval_id: str) -> bool:
        """Deny a pending action."""
        req = request.Request(
            self._url(f"{ENDPOINT_DENY}{approval_id}"),
            headers=self._auth_headers(),
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout):
                return True
        except error.URLError:
            return False

    def wait_for_approval(
        self,
        approval_id: str,
        timeout: int = DEFAULT_APPROVAL_TIMEOUT,
        poll_interval: int = DEFAULT_POLL_INTERVAL,
    ) -> CheckResult:
        """Block until a pending action is approved or denied (or timeout).

        Sends the API key on every poll (/v1/status is auth-gated on
        servers run with --api-key). Polls are jittered to
        ``[0.8, 1.2] * poll_interval`` so many waiting clients don't poll in
        lockstep. HTTP 401/403 raise :class:`VanzikAuthError` at once rather
        than end in a timeout DENY that hides the bad key; other HTTP,
        transport and body errors are retried until the deadline.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            req = request.Request(
                self._url(f"{ENDPOINT_STATUS}{approval_id}"),
                headers=self._auth_headers(),
                method="GET",
            )
            try:
                with request.urlopen(req, timeout=self.timeout) as resp:
                    body = json.loads(resp.read())
                    if body.get("status") == "resolved" and body.get("decision") in (
                        DECISION_ALLOW,
                        DECISION_DENY,
                    ):
                        return CheckResult(
                            decision=body["decision"],
                            reason=body.get("reason", "resolved"),
                        )
            except error.HTTPError as e:
                if e.code in (401, 403):
                    raise VanzikAuthError(
                        f"Vanzik rejected status poll for "
                        f"{approval_id!r} with HTTP {e.code} "
                        f"(check api_key)",
                        status=e.code,
                    )
                # Other HTTPErrors (5xx, transient): keep polling.
            except (error.URLError, OSError, ValueError):
                # Transport error or a non-JSON body (a middlebox page served
                # with 200): keep polling; a malformed poll body must never
                # raise out of the waiting agent.
                pass
            # Non-cryptographic jitter is fine here.
            actual_sleep = poll_interval * (0.8 + 0.4 * random.random())
            time.sleep(actual_sleep)

        return CheckResult(decision=DECISION_DENY, reason="Approval timed out")
