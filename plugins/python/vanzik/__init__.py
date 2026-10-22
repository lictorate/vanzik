"""
Vanzik Python SDK

Lightweight client for checking actions against Vanzik policies.

Usage:
    from vanzik import Guard

    guard = Guard("http://localhost:8080")
    result = guard.check("shell", command="rm -rf ./data")

    if result.allowed:
        execute(command)
    elif result.needs_approval:
        print(f"Approve at: {result.approval_url}")
    else:
        print(f"Blocked: {result.reason}")

The client, results, exceptions and constants live in :mod:`vanzik.core`,
``@guarded`` in :mod:`vanzik.decorators`, framework integrations in
:mod:`vanzik.adapters`. Import public names from the package root.
"""

# The SDK's release version; scripts/bump-version.sh keeps it in step with
# pyproject.toml.
__version__ = "2.0.0"

# Back-compat module aliases: they keep ``vanzik.request.urlopen``,
# ``vanzik.time.sleep``, ... valid mock.patch targets. Patching through
# them mutates the shared stdlib module, so it intercepts vanzik.core's
# calls. Do not remove without a deprecation cycle.
import functools  # noqa: F401
import json  # noqa: F401
import logging  # noqa: F401
import os  # noqa: F401
import random  # noqa: F401
import time  # noqa: F401
from urllib import request, error  # noqa: F401
from urllib.parse import quote as urlquote  # noqa: F401

from vanzik.core import (
    DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT,
    DEFAULT_APPROVAL_TIMEOUT,
    DEFAULT_POLL_INTERVAL,
    DECISION_ALLOW,
    DECISION_DENY,
    DECISION_REQUIRE_APPROVAL,
    ENDPOINT_CHECK,
    ENDPOINT_APPROVE,
    ENDPOINT_DENY,
    ENDPOINT_STATUS,
    LOCAL_TENANT_ID,
    FAIL_MODE_DENY,
    FAIL_MODE_ALLOW,
    VanzikError,
    VanzikDenied,
    VanzikApprovalRequired,
    VanzikApprovalTimeout,
    VanzikAuthError,
    VanzikTimeoutError,
    CheckResult,
    Guard,
    log,
)
from vanzik.decorators import guarded


# Public API surface. Everything else is internal.
__all__ = [
    "__version__",
    "Guard",
    "CheckResult",
    "guarded",
    "VanzikError",
    "VanzikDenied",
    "VanzikApprovalRequired",
    "VanzikApprovalTimeout",
    "VanzikAuthError",
    "DEFAULT_BASE_URL",
    "DEFAULT_TIMEOUT",
    "DEFAULT_APPROVAL_TIMEOUT",
    "DEFAULT_POLL_INTERVAL",
    "DECISION_ALLOW",
    "DECISION_DENY",
    "DECISION_REQUIRE_APPROVAL",
    "LOCAL_TENANT_ID",
    "FAIL_MODE_DENY",
    "FAIL_MODE_ALLOW",
]
