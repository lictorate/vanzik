"""Statistical contract test for ``Guard.wait_for_approval`` jitter.

Across >=30 captured sleep durations: (a) coefficient of variation > 0.05
(a real RNG drives it) and (b) every duration within ``[0.75 * pi, 1.25 *
pi]`` (bounded). ``test_sdk_polish.py`` has the per-sample 80%-120% check.

``time.sleep`` is patched through ``vanzik.time.sleep`` to record the
requested duration and sleep zero.

The thresholds are generous: CoV > 0.05 is a few sigma below the
theoretical ~0.116 of uniform [0.8, 1.2]. If this flakes, raise the
sample size (to 100); don't relax the threshold.
"""

from __future__ import annotations

import math
import statistics
import time
from unittest.mock import patch

import pytest

from vanzik import Guard
from tests.conftest import MockVanzikHandler


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _capture_sleeps(num_polls: int, poll_interval: float, mock_server: str) -> list[float]:
    """Drive ``wait_for_approval`` for at least ``num_polls`` iterations and
    return the list of requested sleep durations."""
    MockVanzikHandler.status_response = {"id": "ap_jit", "status": "pending"}

    sleeps: list[float] = []

    real_sleep = time.sleep

    def capturing_sleep(s: float) -> None:
        sleeps.append(s)
        # Don't burn wall-time; yield once.
        real_sleep(0)

    g = Guard(mock_server, api_key="k")
    deadline = time.time() + 30  # plenty
    target = num_polls

    def short_circuit_sleep(s: float) -> None:
        sleeps.append(s)
        real_sleep(0)
        if len(sleeps) >= target:
            # A BaseException sentinel propagates out of wait_for_approval.
            raise _StopJitterLoop()

    class _StopJitterLoop(BaseException):
        pass

    try:
        with patch("vanzik.time.sleep", side_effect=short_circuit_sleep):
            try:
                g.wait_for_approval(
                    "ap_jit",
                    timeout=int(num_polls * poll_interval * 5) + 1,
                    poll_interval=int(poll_interval) if poll_interval >= 1 else 1,
                )
            except _StopJitterLoop:
                pass
    finally:
        pass

    return sleeps


# ---------------------------------------------------------------------------
# Contract test — statistical jitter
# ---------------------------------------------------------------------------


def test_jitter_distribution_is_random_and_bounded(mock_server):
    """Across 30+ polls, jitter durations are non-degenerate and bounded.

    Bounded: every duration lies in ``[0.75 * poll_interval, 1.25 *
    poll_interval]`` (±25% slack; the SDK uses ±20%).

    Non-degenerate: coefficient-of-variation (stddev/mean) > 0.05. Pure
    uniform on ``[0.8, 1.2]`` has CoV ≈ 0.116 — at 30 samples the chance
    of falling below 0.05 by random luck is < 0.1%.

    ``poll_interval`` is an ``int`` in the public API, hence 1 second.
    """
    poll_interval = 1.0
    sleeps = _capture_sleeps(num_polls=30, poll_interval=poll_interval, mock_server=mock_server)

    assert len(sleeps) >= 30, f"only captured {len(sleeps)} sleeps"

    lo, hi = 0.75 * poll_interval, 1.25 * poll_interval
    for s in sleeps:
        assert lo <= s <= hi, (
            f"sleep duration {s:.4f}s out of [{lo}, {hi}] band; "
            f"all samples = {sleeps!r}"
        )

    # Coefficient of variation.
    mu = statistics.fmean(sleeps)
    sigma = statistics.pstdev(sleeps)
    cov = sigma / mu if mu > 0 else 0.0

    # The contract: CoV > 0.05. Theoretical for uniform [0.8, 1.2]
    # = (0.4/sqrt(12)) / 1.0 ≈ 0.1155.
    assert cov > 0.05, (
        f"coefficient of variation {cov:.4f} too low — jitter is not random "
        f"(mean={mu:.4f}, stddev={sigma:.4f}, n={len(sleeps)}). "
        f"If this test flakes intermittently, raise the sample size — "
        f"do NOT lower the threshold."
    )


def test_jitter_durations_are_not_constant(mock_server):
    """At least 5 distinct values appear in 30 samples (jitter is real).

    A constant-pole regression (``time.sleep(poll_interval)``) would fail
    this test outright. A weak RNG that returned a fixed value would also
    fail. The threshold of 5 distinct floats is forgiving — uniform-random
    with 30 samples will produce ~30 distinct floats.
    """
    sleeps = _capture_sleeps(num_polls=30, poll_interval=1.0, mock_server=mock_server)
    distinct = len(set(sleeps))
    assert distinct >= 5, (
        f"only {distinct} distinct sleep durations across {len(sleeps)} polls "
        f"— jitter looks broken or pinned. samples = {sleeps!r}"
    )


def test_jitter_mean_close_to_poll_interval(mock_server):
    """The jitter is centred — mean across many samples ≈ poll_interval.

    For a uniform [0.8 * pi, 1.2 * pi] distribution the population mean
    is exactly ``pi``. With 60 samples the standard error of the mean is
    about ``0.115 / sqrt(60) ≈ 0.015``. We allow a 10% margin (5σ-ish) for
    flake resistance.
    """
    poll_interval = 1.0
    sleeps = _capture_sleeps(num_polls=60, poll_interval=poll_interval, mock_server=mock_server)
    mu = statistics.fmean(sleeps)
    assert math.isclose(mu, poll_interval, rel_tol=0.10), (
        f"mean sleep {mu:.4f} not within 10% of poll_interval {poll_interval} "
        f"(n={len(sleeps)})"
    )
