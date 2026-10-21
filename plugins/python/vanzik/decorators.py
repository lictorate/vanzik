"""The ``@guarded`` decorator: policy-check-then-call for plain
functions. Framework integrations live in ``vanzik.adapters``.
"""

import functools
from typing import Optional

from vanzik.core import (
    DEFAULT_APPROVAL_TIMEOUT,
    DEFAULT_POLL_INTERVAL,
    VanzikApprovalRequired,
    VanzikApprovalTimeout,
    VanzikDenied,
    Guard,
)

# Kwargs ``guarded(**check_kwargs)`` may forward to ``Guard.check``. Anything
# else is almost always a typo (``agent="x"`` for ``meta={"agent": "x"}``),
# so it is rejected at definition time instead of failing at call time.
_GUARDED_VALID_CHECK_KWARGS = frozenset({
    "action",
    "command",
    "path",
    "domain",
    "url",
    "session_id",
    "parent_session_id",
    "est_cost",
    "meta",
})


def guarded(
    scope: str,
    guard: Optional[Guard] = None,
    *,
    wait_for_approval: bool = False,
    approval_timeout: int = DEFAULT_APPROVAL_TIMEOUT,
    approval_poll_interval: int = DEFAULT_POLL_INTERVAL,
    **check_kwargs,
):
    """Decorator that checks policy before executing a function.

    Default behavior:
        @guarded("shell", guard=guard)
        def run_command(cmd: str):
            os.system(cmd)

        run_command("ls")        # executes if ALLOW
        run_command("rm -rf /")  # raises VanzikDenied (a PermissionError)

    Opt-in block-until-resolved:
        @guarded(
            "cost",
            guard=guard,
            wait_for_approval=True,
            approval_timeout=300,
            approval_poll_interval=2,
        )
        def expensive_call(prompt: str):
            ...

    On REQUIRE_APPROVAL, with ``wait_for_approval=True`` the wrapper calls
    :meth:`Guard.wait_for_approval` and then dispatches on the resolved
    decision. A resolved ALLOW is *replayed* through ``guard.check`` with
    ``approval_id`` set — that replay is what consumes the one-shot
    approval, enforces ``--approval-validity``, reserves cost for
    cost-scoped actions, and audits the execution — and the function runs
    only if the replay allows. A resolved DENY or a denied replay raises
    :class:`VanzikDenied`; a refused replay that re-entered the approval
    flow raises :class:`VanzikApprovalRequired` carrying the new id (the
    wrapper never waits a second time on its own); a synthetic "Approval
    timed out" raises :class:`VanzikApprovalTimeout`.
    With ``wait_for_approval=False`` (default), the wrapper raises
    :class:`VanzikApprovalRequired` immediately. All these exceptions
    extend ``PermissionError``.

    ``**check_kwargs`` are forwarded to :meth:`Guard.check` (``action``,
    ``command``, ``path``, ``domain``, ``url``, ``session_id``,
    ``parent_session_id``, ``est_cost``, ``meta``); any other key raises
    ``TypeError`` at decoration time.
    """
    unknown = set(check_kwargs) - _GUARDED_VALID_CHECK_KWARGS
    if unknown:
        raise TypeError(
            f"@guarded got unexpected keyword arguments: "
            f"{sorted(unknown)!r}. Valid options: "
            f"{sorted(_GUARDED_VALID_CHECK_KWARGS)!r}"
        )

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            g = guard or Guard()
            cmd = args[0] if args else kwargs.get("command", kwargs.get("cmd", ""))
            result = g.check(scope, command=str(cmd), **check_kwargs)

            if result.allowed:
                return func(*args, **kwargs)

            if result.needs_approval:
                if wait_for_approval:
                    resolved = g.wait_for_approval(
                        result.approval_id,
                        timeout=approval_timeout,
                        poll_interval=approval_poll_interval,
                    )
                    if resolved.allowed:
                        # The status poll is read-only; only this replay
                        # spends the one-shot approval.
                        replay = g.check(
                            scope,
                            command=str(cmd),
                            approval_id=result.approval_id,
                            **check_kwargs,
                        )
                        if replay.allowed:
                            return func(*args, **kwargs)
                        if replay.needs_approval:
                            # Consumed or expired, re-issued under a new id.
                            # Don't wait again: a refused replay would loop
                            # forever.
                            raise VanzikApprovalRequired(
                                f"Action requires approval. Approve at: {replay.approval_url}",
                                result=replay,
                                approval_id=replay.approval_id,
                                approval_url=replay.approval_url,
                            )
                        raise VanzikDenied(
                            f"Action denied by Vanzik: {replay.reason}",
                            result=replay,
                        )
                    if resolved.denied and resolved.reason == "Approval timed out":
                        raise VanzikApprovalTimeout(
                            f"Approval for {result.approval_id} timed out after "
                            f"{approval_timeout}s",
                            result=resolved,
                            approval_id=result.approval_id,
                        )
                    raise VanzikDenied(
                        f"Action denied by Vanzik: {resolved.reason}",
                        result=resolved,
                    )
                raise VanzikApprovalRequired(
                    # Stable message text — text-matchers in caller code
                    # depend on it.
                    f"Action requires approval. Approve at: {result.approval_url}",
                    result=result,
                    approval_id=result.approval_id,
                    approval_url=result.approval_url,
                )

            raise VanzikDenied(
                f"Action denied by Vanzik: {result.reason}",
                result=result,
            )
        return wrapper
    return decorator
