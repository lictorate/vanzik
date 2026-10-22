"""
Vanzik CrewAI adapter.

``GuardedCrewTool`` subclasses CrewAI's ``BaseTool`` (CrewAI 1.x with
pydantic 2.12 rejects virtual-subclass registration via
``BaseTool.register``). Instead of an ``__getattr__`` allowlist, every
entry point the framework calls is overridden and gated:

  - ``_run`` (abstract on the parent): ``BaseTool.run``, ``invoke`` and
    ``to_structured_tool`` all read ``_run`` off the instance.
  - ``_arun``: CrewAI's ``arun`` calls it.
  - ``run`` / ``arun`` / ``invoke`` / ``ainvoke`` / ``__call__``: gated
    whichever entry the runtime picks; each forwards to the wrapped
    tool's matching method so CrewAI's usage accounting
    (``_claim_usage``) still runs.
  - ``to_structured_tool``: the structured tool's ``func`` is our gated
    ``_run``, not the wrapped tool's bare one.

The canary test ``test_at_real_crewai.py`` trips if upstream adds a
dispatch path that bypasses these overrides. Pydantic ``PrivateAttr``
keeps ``_tool``, ``_guard`` and ``_scope`` out of ``model_fields`` and
``model_dump``.

``crewai`` is imported on first instantiation, so ``pip install vanzik``
works without the extra; until then ``GuardedCrewTool`` is a factory
that raises a clear ``ImportError``.

Usage
-----
    from vanzik.adapters.crewai import GuardedCrewTool, guard_crew_tools

    guarded = GuardedCrewTool(my_tool, guard_url="http://localhost:8080")

    tools = guard_crew_tools(
        tools=[tool_a, tool_b],
        guard_url="http://localhost:8080",
        agent_id="my-crew-agent",
    )
"""

from __future__ import annotations

import asyncio
from typing import Any, List, Optional

from vanzik import (
    DEFAULT_BASE_URL,
    VanzikApprovalRequired,
    VanzikDenied,
    Guard,
)
from vanzik.adapters._common import (
    ConflictingToolInput,
    conflict_denial,
    extract_check_params,
)


# ---------------------------------------------------------------------------
# Lazy CrewAI BaseTool resolution. Importing crewai is heavy (LiteLLM, the
# OpenAI client); a missing or mismatched CrewAI raises a clear ImportError
# instead of an AttributeError deep inside pydantic.
# ---------------------------------------------------------------------------

_CREWAI_BASETOOL: Optional[type] = None
_GUARDED_CLASS: Optional[type] = None



def _accepted_kwargs(cls: Any, kwargs: dict) -> dict:
    """Keep only the keyword arguments ``cls.__init__`` accepts.

    CrewStructuredTool's constructor differs across CrewAI releases: 1.x is
    a pydantic model that takes any field as a keyword, while 0.19x names
    its parameters explicitly and has no ``cache_function``. An unknown
    keyword raises TypeError.
    """
    import inspect

    try:
        params = inspect.signature(cls.__init__).parameters
    except (TypeError, ValueError):
        return kwargs
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return kwargs
    return {k: v for k, v in kwargs.items() if k in params}

def _is_valid_args_schema(value: Any) -> bool:
    """Return True if ``value`` is a pydantic BaseModel subclass or a
    JSON-schema-shaped dict, i.e. something BaseTool init accepts (not a
    MagicMock)."""
    if isinstance(value, dict):
        return True
    try:
        from pydantic import BaseModel  # type: ignore[import-not-found]
        return isinstance(value, type) and issubclass(value, BaseModel)
    except Exception:
        return False


# CrewAI releases before 1.0 dispatch an agent's tool calls through a path
# this adapter does not wrap: a crew kickoff on crewai 0.193 ran the tool
# without a single /v1/check call. Refuse them rather than hand back tools
# that look gated but aren't.
_MIN_CREWAI = (1, 0)


def _require_supported_crewai() -> None:
    try:
        from importlib.metadata import version

        found = version("crewai")
    except Exception:
        return  # not installed: the import below raises the install hint
    parts = []
    for piece in found.split(".")[:2]:
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    if tuple(parts) < _MIN_CREWAI:
        raise ImportError(
            f"vanzik CrewAI adapter requires crewai>=1.0 (found {found}). "
            "Older CrewAI runs agent tool calls outside the adapter's gate. "
            "Upgrade with `pip install -U 'crewai>=1.0,<2.0'`."
        )


def _resolve_crewai_basetool() -> type:
    """Return ``crewai.tools.BaseTool`` (cached) or raise a clear ImportError."""
    global _CREWAI_BASETOOL
    if _CREWAI_BASETOOL is not None:
        return _CREWAI_BASETOOL
    _require_supported_crewai()
    last_err: Optional[Exception] = None
    for module_name, attr in (
        ("crewai.tools", "BaseTool"),
        ("crewai.tools.base_tool", "BaseTool"),
    ):
        try:
            module = __import__(module_name, fromlist=[attr])
            base = getattr(module, attr, None)
            if base is not None:
                _CREWAI_BASETOOL = base
                return base
        except ImportError as e:
            last_err = e
            continue
    raise ImportError(
        "vanzik CrewAI adapter requires the `crewai` package. "
        "Install it with `pip install 'vanzik[crewai]'`. "
        f"(underlying import error: {last_err!r})"
    )


def _build_guarded_class() -> type:
    """Build the GuardedCrewTool class once and cache it, so isinstance
    checks stay stable."""
    global _GUARDED_CLASS
    if _GUARDED_CLASS is not None:
        return _GUARDED_CLASS

    BaseTool = _resolve_crewai_basetool()
    # Imported here so the SDK does not need pydantic at module load time.
    from pydantic import PrivateAttr  # type: ignore[import-not-found]

    class GuardedCrewTool(BaseTool):  # type: ignore[misc, valid-type]
        """A CrewAI ``BaseTool`` that gates every entry point through
        :meth:`Guard.check` before forwarding to the wrapped tool."""

        # Private attrs: not validated, not in model_fields or model_dump.
        # Set per instance in __init__.
        _tool: Any = PrivateAttr(default=None)
        _guard: Any = PrivateAttr(default=None)
        _scope: str = PrivateAttr(default="shell")

        # ----------------------------------------------------------
        # Construction
        # ----------------------------------------------------------

        def __init__(  # type: ignore[no-untyped-def]
            self,
            tool: Any,
            guard: Optional[Guard] = None,
            guard_url: str = DEFAULT_BASE_URL,
            agent_id: str = "",
            scope: str = "shell",
            **_extra: Any,
        ) -> None:
            # BaseTool requires str name/description: take them from the
            # wrapped tool (coercing mocks). args_schema is forwarded only
            # when BaseTool would accept it.
            name_attr = getattr(tool, "name", type(tool).__name__)
            desc_attr = getattr(tool, "description", "")
            init_kwargs: dict = {
                "name": str(name_attr) if not isinstance(name_attr, str) else name_attr,
                "description": (
                    str(desc_attr) if not isinstance(desc_attr, str) else desc_attr
                ),
            }
            args_schema = getattr(tool, "args_schema", None)
            if args_schema is not None and _is_valid_args_schema(args_schema):
                init_kwargs["args_schema"] = args_schema
            super().__init__(**init_kwargs)
            # object.__setattr__ bypasses any pydantic __setattr__ override.
            object.__setattr__(self, "_tool", tool)
            object.__setattr__(
                self,
                "_guard",
                guard if guard is not None else Guard(guard_url, agent_id=agent_id),
            )
            object.__setattr__(self, "_scope", scope)

        # ----------------------------------------------------------
        # Scope inference and parameter extraction
        # ----------------------------------------------------------

        def _infer_scope(self, tool_input: Any) -> str:
            """Infer scope from runtime input or static metadata."""
            if isinstance(tool_input, dict):
                if tool_input.get("url") or tool_input.get("domain"):
                    return "network"
                if tool_input.get("path") or tool_input.get("file_path"):
                    return "filesystem"
            combined = f"{self.name} {self.description}".lower()
            if any(kw in combined for kw in ["http", "api", "fetch", "request", "url", "web"]):
                return "network"
            if any(kw in combined for kw in ["file", "read", "write", "directory", "path"]):
                return "filesystem"
            if any(kw in combined for kw in ["browser", "navigate", "click", "page"]):
                return "browser"
            return self._scope

        def _extract_check_params(self, tool_input: Any) -> dict:
            """Extract check params from str/dict tool input."""
            return extract_check_params(tool_input, self.name)

        # ----------------------------------------------------------
        # The single shared gate.
        # ----------------------------------------------------------

        def _check_or_raise(self, tool_input: Any) -> None:
            """Run the policy check and raise on DENY / REQUIRE_APPROVAL."""
            try:
                params = self._extract_check_params(tool_input)
            except ConflictingToolInput as e:
                result = conflict_denial(e)
            else:
                scope = self._infer_scope(tool_input)
                result = self._guard.check(scope, **params)

            if result.allowed:
                return
            if result.needs_approval:
                raise VanzikApprovalRequired(
                    f"[Vanzik] Action requires approval. "
                    f"Approve at: {result.approval_url}\n"
                    f"Reason: {result.reason}",
                    result=result,
                )
            raise VanzikDenied(
                f"[Vanzik] Action denied.\nReason: {result.reason}",
                result=result,
            )

        @staticmethod
        def _normalize_tool_input(args: tuple, kwargs: dict) -> Any:
            """Map *args/**kwargs onto a single ``tool_input`` for the gate."""
            if args:
                return args[0] if len(args) == 1 else list(args)
            if kwargs:
                return dict(kwargs)
            return ""

        # ----------------------------------------------------------
        # Synchronous entry points
        # ----------------------------------------------------------

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            """Internal CrewAI sync entry (the parent's abstract ``_run``);
            ``to_structured_tool`` uses it as ``func``."""
            tool_input = self._normalize_tool_input(args, kwargs)
            self._check_or_raise(tool_input)
            inner = self._tool
            if hasattr(inner, "_run"):
                return inner._run(*args, **kwargs)
            if hasattr(inner, "run"):
                return inner.run(*args, **kwargs)
            raise AttributeError(
                f"wrapped tool {type(inner).__name__!r} has neither _run nor run"
            )

        def run(self, *args: Any, **kwargs: Any) -> Any:
            """Public sync entry. Gated before CrewAI's ``_claim_usage``
            accounting, so a denied call does not consume a usage slot; on
            ALLOW the wrapped tool's ``run`` does its own accounting.
            """
            tool_input = self._normalize_tool_input(args, kwargs)
            self._check_or_raise(tool_input)
            inner = self._tool
            if hasattr(inner, "run"):
                return inner.run(*args, **kwargs)
            if hasattr(inner, "_run"):
                return inner._run(*args, **kwargs)
            raise AttributeError(
                f"wrapped tool {type(inner).__name__!r} has neither run nor _run"
            )

        def invoke(  # type: ignore[override]
            self,
            input: Any = None,  # noqa: A002 — match Runnable signature
            config: Any = None,
            **kwargs: Any,
        ) -> Any:
            """Modern Runnable entry (``tool.invoke(input=..., config=...)``).
            Gated, whether or not the parent defines ``invoke``."""
            self._check_or_raise(input)
            inner = self._tool
            if hasattr(inner, "invoke"):
                return inner.invoke(input, config=config, **kwargs)
            if hasattr(inner, "_run"):
                return inner._run(input, **kwargs) if not isinstance(input, dict) else inner._run(**input, **kwargs)
            if hasattr(inner, "run"):
                return inner.run(input, **kwargs)
            raise AttributeError(
                f"wrapped tool {type(inner).__name__!r} exposes no sync entry"
            )

        def __call__(self, *args: Any, **kwargs: Any) -> Any:
            """Direct call (``tool(input)``). Gated."""
            tool_input = self._normalize_tool_input(args, kwargs)
            self._check_or_raise(tool_input)
            inner = self._tool
            if callable(inner):
                try:
                    return inner(*args, **kwargs)
                except TypeError:
                    # Some pydantic versions make BaseModel instances
                    # callable but reject positional args: fall through.
                    pass
            if hasattr(inner, "invoke"):
                return inner.invoke(args[0] if args else kwargs)
            if hasattr(inner, "_run"):
                return inner._run(*args, **kwargs)
            if hasattr(inner, "run"):
                return inner.run(*args, **kwargs)
            raise AttributeError(
                f"wrapped tool {type(inner).__name__!r} is not callable"
            )

        # ----------------------------------------------------------
        # Async entry points
        # ----------------------------------------------------------

        async def _arun(self, *args: Any, **kwargs: Any) -> Any:
            """Internal async entry. Gated.

            CrewAI's ``BaseTool._arun`` raises NotImplementedError, so on
            ALLOW this tries the wrapped tool's ``_arun``, then ``arun``,
            then its sync path in a thread executor.
            """
            tool_input = self._normalize_tool_input(args, kwargs)
            self._check_or_raise(tool_input)
            inner = self._tool
            if hasattr(inner, "_arun"):
                try:
                    return await inner._arun(*args, **kwargs)
                except NotImplementedError:
                    pass
            if hasattr(inner, "arun"):
                try:
                    return await inner.arun(*args, **kwargs)
                except NotImplementedError:
                    pass
            loop = asyncio.get_running_loop()
            if hasattr(inner, "_run"):
                return await loop.run_in_executor(
                    None, lambda: inner._run(*args, **kwargs)
                )
            if hasattr(inner, "run"):
                return await loop.run_in_executor(
                    None, lambda: inner.run(*args, **kwargs)
                )
            raise AttributeError(
                f"wrapped tool {type(inner).__name__!r} exposes no async path"
            )

        async def arun(self, *args: Any, **kwargs: Any) -> Any:
            """Public async entry. Gated. See ``_arun`` for fallthrough notes."""
            tool_input = self._normalize_tool_input(args, kwargs)
            self._check_or_raise(tool_input)
            inner = self._tool
            if hasattr(inner, "arun"):
                try:
                    return await inner.arun(*args, **kwargs)
                except NotImplementedError:
                    pass
            if hasattr(inner, "_arun"):
                try:
                    return await inner._arun(*args, **kwargs)
                except NotImplementedError:
                    pass
            loop = asyncio.get_running_loop()
            if hasattr(inner, "_run"):
                return await loop.run_in_executor(
                    None, lambda: inner._run(*args, **kwargs)
                )
            if hasattr(inner, "run"):
                return await loop.run_in_executor(
                    None, lambda: inner.run(*args, **kwargs)
                )
            raise AttributeError(
                f"wrapped tool {type(inner).__name__!r} exposes no async path"
            )

        async def ainvoke(  # type: ignore[override]
            self,
            input: Any = None,  # noqa: A002
            config: Any = None,
            **kwargs: Any,
        ) -> Any:
            """Modern async Runnable entry. Gated."""
            self._check_or_raise(input)
            inner = self._tool
            if hasattr(inner, "ainvoke"):
                try:
                    return await inner.ainvoke(input, config=config, **kwargs)
                except NotImplementedError:
                    pass
            if hasattr(inner, "_arun"):
                try:
                    return await inner._arun(input, **kwargs)
                except NotImplementedError:
                    pass
            if hasattr(inner, "arun"):
                try:
                    return await inner.arun(input, **kwargs)
                except NotImplementedError:
                    pass
            loop = asyncio.get_running_loop()
            if hasattr(inner, "invoke"):
                return await loop.run_in_executor(
                    None, lambda: inner.invoke(input, config=config, **kwargs)
                )
            if hasattr(inner, "_run"):
                return await loop.run_in_executor(
                    None, lambda: inner._run(input, **kwargs)
                )
            if hasattr(inner, "run"):
                return await loop.run_in_executor(
                    None, lambda: inner.run(input, **kwargs)
                )
            raise AttributeError(
                f"wrapped tool {type(inner).__name__!r} exposes no async path"
            )

        # ----------------------------------------------------------
        # to_structured_tool override
        # ----------------------------------------------------------

        def to_structured_tool(self) -> Any:
            """Convert to a CrewStructuredTool whose ``func`` is our
            gated ``_run``, so the conversion does not bypass the gate.
            """
            from crewai.tools.structured_tool import CrewStructuredTool  # type: ignore

            self._set_args_schema()
            kwargs = {
                "name": self.name,
                "description": self.description,
                "args_schema": self.args_schema,
                "func": self._run,  # gated
                "result_as_answer": getattr(self, "result_as_answer", False),
                "max_usage_count": getattr(self, "max_usage_count", None),
                "current_usage_count": getattr(self, "current_usage_count", 0),
                "cache_function": getattr(self, "cache_function", None),
            }
            structured_tool = CrewStructuredTool(**_accepted_kwargs(CrewStructuredTool, kwargs))
            structured_tool._original_tool = self
            return structured_tool

        # ----------------------------------------------------------
        # model_dump: hide private gating fields. PrivateAttr already
        # excludes them; this is belt and braces.
        # ----------------------------------------------------------

        def model_dump(self, *args: Any, **kwargs: Any) -> dict:  # type: ignore[override]
            data = super().model_dump(*args, **kwargs)
            for k in ("_tool", "_guard", "_scope"):
                data.pop(k, None)
            return data

    _GUARDED_CLASS = GuardedCrewTool
    return GuardedCrewTool


# ---------------------------------------------------------------------------
# Public GuardedCrewTool symbol: a factory, so importing it needs no crewai.
# ---------------------------------------------------------------------------


class _GuardedCrewToolFactory:
    """Factory whose ``__call__`` builds (once) and instantiates the real
    GuardedCrewTool class.

    ``isinstance`` / ``issubclass`` delegate to the real class once built
    (False before that). The real class is :func:`_build_guarded_class`.
    """

    def __call__(self, tool: Any, *args: Any, **kwargs: Any) -> Any:
        cls = _build_guarded_class()
        return cls(tool, *args, **kwargs)

    def __instancecheck__(self, obj: Any) -> bool:  # pragma: no cover - delegated
        cls = _GUARDED_CLASS
        if cls is None:
            return False
        return isinstance(obj, cls)

    def __subclasscheck__(self, sub: Any) -> bool:  # pragma: no cover - delegated
        cls = _GUARDED_CLASS
        if cls is None:
            return False
        return issubclass(sub, cls)

    def __repr__(self) -> str:  # pragma: no cover
        return "<GuardedCrewTool factory (lazy crewai.BaseTool subclass)>"


GuardedCrewTool = _GuardedCrewToolFactory()


def guard_crew_tools(
    tools: List[Any],
    guard_url: str = DEFAULT_BASE_URL,
    agent_id: str = "",
    default_scope: str = "shell",
) -> List[Any]:
    """Wrap a list of CrewAI tools with Vanzik enforcement.

    Args:
        tools: List of CrewAI tools to guard.
        guard_url: URL of the Vanzik proxy.
        agent_id: Identifier for this agent in audit logs.
        default_scope: Default policy scope.

    Returns:
        List of guarded tool instances sharing one :class:`Guard`.
    """
    cls = _build_guarded_class()
    guard = Guard(guard_url, agent_id=agent_id)
    return [cls(tool, guard=guard, scope=default_scope) for tool in tools]
