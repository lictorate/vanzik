/**
 * Statistical contract test for `Vanzik.waitForApproval` jitter:
 *
 *   - Capture every `setTimeout` delay across >=30 polls.
 *   - Assert each delay is in the ±25% band of `pollIntervalMs`.
 *   - Assert coefficient-of-variation > 0.05 (the jitter is real, not pinned).
 *   - Assert >=5 distinct values in 30 samples (rules out fixed-noise stubs).
 *
 * `sdk_polish.test.ts` checks the per-iteration band; this file checks the
 * distribution. `setTimeout` is replaced by a recording spy that runs the
 * callback with delay 0, so the test takes milliseconds.
 */

import { Vanzik } from "../index";

// ---------------------------------------------------------------------------
// fetch + setTimeout plumbing
// ---------------------------------------------------------------------------

type FetchArgs = [string | URL, RequestInit?];
type FetchMock = jest.Mock<Promise<Response>, FetchArgs>;

function installFetchMock(): FetchMock {
  const m = jest.fn() as unknown as FetchMock;
  (globalThis as { fetch: unknown }).fetch = m;
  return m;
}

function pendingResponse(): Response {
  return new Response(JSON.stringify({ id: "ap_jit", status: "pending" }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function resolvedAllowResponse(): Response {
  return new Response(
    JSON.stringify({
      id: "ap_jit",
      status: "resolved",
      decision: "ALLOW",
      reason: "test-resolve",
    }),
    {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }
  );
}

/**
 * Wire up a fetch mock that returns "pending" until at least `target`
 * polls have happened, then flips to "resolved" so the loop returns
 * without waiting for the wall-clock deadline.
 */
function pendingThenResolvedFetch(target: number, sleeps: number[]): FetchMock {
  const m = installFetchMock();
  m.mockImplementation(async () => {
    if (sleeps.length >= target) {
      return resolvedAllowResponse();
    }
    return pendingResponse();
  });
  return m;
}

interface CapturedSleeps {
  sleeps: number[];
  restore: () => void;
}

/**
 * Every SDK request arms an abort timer with the client `timeout`. This
 * distinctive value, far outside the jitter band, lets the spy drop those
 * samples.
 */
const REQUEST_TIMEOUT = 4321;

/** Spy on setTimeout to capture every requested jitter delay. */
function spyOnSetTimeout(): CapturedSleeps {
  const sleeps: number[] = [];
  const original = global.setTimeout;
  const spy = jest
    .spyOn(global, "setTimeout")
    .mockImplementation(((cb: () => void, ms: number) => {
      // Skip the per-request abort timer; only jitter sleeps are sampled.
      if (ms !== REQUEST_TIMEOUT) sleeps.push(ms);
      return original(cb, 0);
    }) as typeof global.setTimeout);
  return { sleeps, restore: () => spy.mockRestore() };
}

const ORIGINAL_ENV = { ...process.env };

beforeEach(() => {
  delete process.env.VANZIK_URL;
  delete process.env.VANZIK_API_KEY;
});

afterAll(() => {
  process.env = ORIGINAL_ENV;
});

// ---------------------------------------------------------------------------
// Statistical helpers
// ---------------------------------------------------------------------------

function mean(xs: number[]): number {
  return xs.reduce((a, b) => a + b, 0) / xs.length;
}

function pstdev(xs: number[]): number {
  const mu = mean(xs);
  const v = xs.reduce((acc, x) => acc + (x - mu) * (x - mu), 0) / xs.length;
  return Math.sqrt(v);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("waitForApproval jitter — distribution shape", () => {
  test("durations are bounded and coefficient-of-variation > 0.05", async () => {
    const POLL = 100; // ms — chosen so the bounds [80, 120] are integer-friendly
    const TARGET = 30;
    const { sleeps, restore } = spyOnSetTimeout();
    pendingThenResolvedFetch(TARGET, sleeps);

    try {
      const g = new Vanzik({ apiKey: "k", timeout: REQUEST_TIMEOUT });
      await g.waitForApproval("ap_jit", 30_000, POLL);
    } finally {
      restore();
    }

    expect(sleeps.length).toBeGreaterThanOrEqual(TARGET);

    // ±25% band, deliberately looser than the SDK's ±20%.
    const lo = 0.75 * POLL;
    const hi = 1.25 * POLL;
    for (const s of sleeps) {
      expect(s).toBeGreaterThanOrEqual(lo);
      expect(s).toBeLessThanOrEqual(hi);
    }

    // Coefficient of variation > 0.05.
    const sample = sleeps.slice(0, TARGET);
    const mu = mean(sample);
    const sigma = pstdev(sample);
    const cov = mu > 0 ? sigma / mu : 0;

    expect(cov).toBeGreaterThan(0.05);
  });

  test("at least 5 distinct durations across 30 samples", async () => {
    const TARGET = 30;
    const { sleeps, restore } = spyOnSetTimeout();
    pendingThenResolvedFetch(TARGET, sleeps);

    try {
      const g = new Vanzik({ apiKey: "k", timeout: REQUEST_TIMEOUT });
      await g.waitForApproval("ap_jit", 30_000, 100);
    } finally {
      restore();
    }

    const sample = sleeps.slice(0, TARGET);
    const distinct = new Set(sample).size;
    // Constant jitter gives 1; a real RNG gives ~30.
    expect(distinct).toBeGreaterThanOrEqual(5);
  });

  test("mean delay across 60 samples is within 10% of pollIntervalMs", async () => {
    const POLL = 100;
    const TARGET = 60;
    const { sleeps, restore } = spyOnSetTimeout();
    pendingThenResolvedFetch(TARGET, sleeps);

    try {
      const g = new Vanzik({ apiKey: "k", timeout: REQUEST_TIMEOUT });
      await g.waitForApproval("ap_jit", 30_000, POLL);
    } finally {
      restore();
    }

    const sample = sleeps.slice(0, TARGET);
    const mu = mean(sample);
    // Theoretical mean for uniform [0.8 * POLL, 1.2 * POLL] is exactly POLL.
    // 60 samples gives a standard error of ~POLL * 0.115 / sqrt(60) ≈ 1.5 ms.
    // Allowing 10% (10 ms) means a >5σ window — robust against flake.
    expect(Math.abs(mu - POLL)).toBeLessThan(POLL * 0.1);
  });
});
