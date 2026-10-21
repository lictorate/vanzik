/**
 * Tests for the Vanzik TypeScript SDK.
 *
 * The SDK is intentionally small and depends only on the native `fetch`
 * + `AbortController`. Tests mock `globalThis.fetch` rather than standing
 * up a real server — the Go-side E2E suite (plugins/python tests) already
 * exercises the real wire contract.
 */

import {
  Vanzik,
  guarded,
  VanzikError,
  VanzikDeniedError,
  VanzikApprovalRequiredError,
  VanzikApprovalTimeoutError,
} from "../index";
import type { CheckOptions, CheckResult } from "../index";

// ---------- fetch mock plumbing ----------

// Node's built-in fetch types (via @types/node) don't re-export RequestInfo,
// so the mock signature is written in terms of the concrete types we
// actually pass in — string | URL and RequestInit.
type FetchArgs = [string | URL, RequestInit?];
type FetchMock = jest.Mock<Promise<Response>, FetchArgs>;

function installFetchMock(): FetchMock {
  const m = jest.fn() as unknown as FetchMock;
  (globalThis as { fetch: unknown }).fetch = m;
  return m;
}

function jsonResponse(body: unknown, init: ResponseInit = { status: 200 }): Response {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { "Content-Type": "application/json", ...(init.headers ?? {}) },
  });
}

// Read the JSON body out of a RequestInit. Handles string bodies (the SDK
// always stringifies before calling fetch). Returns {} if there is no body.
function parseBody(init: RequestInit | undefined): Record<string, unknown> {
  if (!init || typeof init.body !== "string") return {};
  return JSON.parse(init.body as string) as Record<string, unknown>;
}

// ---------- env mock plumbing ----------

const ORIGINAL_ENV = { ...process.env };

beforeEach(() => {
  delete process.env.VANZIK_URL;
  delete process.env.VANZIK_API_KEY;
});

afterAll(() => {
  process.env = ORIGINAL_ENV;
});

// =========================================================================
// Constructor
// =========================================================================

describe("Vanzik constructor", () => {
  test("no args defaults to localhost", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ decision: "ALLOW", reason: "ok" })
    );
    const guard = new Vanzik();
    await guard.check("shell", { command: "ls" });
    const [url] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("http://localhost:8080/v1/check");
  });

  test("string form uses that URL and strips trailing slash", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ decision: "ALLOW", reason: "ok" })
    );
    const guard = new Vanzik("http://example.com:9000/");
    await guard.check("shell", { command: "ls" });
    const [url] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("http://example.com:9000/v1/check");
  });

  test("options form uses baseUrl", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ decision: "ALLOW", reason: "ok" })
    );
    const guard = new Vanzik({ baseUrl: "http://ag.test:8080/" });
    await guard.check("shell", { command: "ls" });
    const [url] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("http://ag.test:8080/v1/check");
  });

  test("VANZIK_URL env is used when no baseUrl supplied", async () => {
    process.env.VANZIK_URL = "http://from-env:8080";
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ decision: "ALLOW", reason: "ok" })
    );
    const guard = new Vanzik();
    await guard.check("shell", { command: "ls" });
    const [url] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("http://from-env:8080/v1/check");
  });

  test("options baseUrl wins over env", async () => {
    process.env.VANZIK_URL = "http://from-env:8080";
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ decision: "ALLOW", reason: "ok" })
    );
    const guard = new Vanzik({ baseUrl: "http://explicit:9000" });
    await guard.check("shell", { command: "ls" });
    const [url] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("http://explicit:9000/v1/check");
  });

  test("string form consults VANZIK_API_KEY env for auth", async () => {
    process.env.VANZIK_API_KEY = "env-key";
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(jsonResponse({ status: "approved", id: "ap_1" }));
    const guard = new Vanzik("http://localhost:8080");
    await guard.approve("ap_1");
    const [, init] = fetchMock.mock.calls[0];
    expect((init?.headers as Record<string, string>).Authorization).toBe(
      "Bearer env-key"
    );
  });

  test("explicit apiKey wins over env", async () => {
    process.env.VANZIK_API_KEY = "env-key";
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(jsonResponse({ status: "approved", id: "ap_1" }));
    const guard = new Vanzik({ apiKey: "explicit-key" });
    await guard.approve("ap_1");
    const [, init] = fetchMock.mock.calls[0];
    expect((init?.headers as Record<string, string>).Authorization).toBe(
      "Bearer explicit-key"
    );
  });
});

// =========================================================================
// check() — wire format and result shape
// =========================================================================

describe("Vanzik.check payload", () => {
  test("converts camelCase options to snake_case wire format", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ decision: "ALLOW", reason: "ok" })
    );
    const guard = new Vanzik({
      baseUrl: "http://localhost:8080",
      agentId: "agent-1",
    });
    await guard.check("network", {
      url: "https://api.example",
      sessionId: "sess-42",
      estCost: 0.25,
      meta: { purpose: "test" },
    });
    const [, init] = fetchMock.mock.calls[0];
    const body = parseBody(init);
    expect(body).toEqual({
      scope: "network",
      agent_id: "agent-1",
      url: "https://api.example",
      session_id: "sess-42",
      est_cost: 0.25,
      meta: { purpose: "test" },
    });
  });

  test("drops estCost when exactly 0", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ decision: "ALLOW", reason: "ok" })
    );
    const guard = new Vanzik();
    await guard.check("cost", { estCost: 0, sessionId: "s" });
    const body = parseBody(fetchMock.mock.calls[0][1]);
    expect(body.est_cost).toBeUndefined();
  });

  test("sends estCost when negative (backend rejects)", async () => {
    // The SDK must forward negatives; the Go backend denies them
    // (deny:cost:negative_value).
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ decision: "DENY", reason: "cost<0" })
    );
    const guard = new Vanzik();
    await guard.check("cost", { estCost: -1, sessionId: "s" });
    const body = parseBody(fetchMock.mock.calls[0][1]);
    expect(body.est_cost).toBe(-1);
  });

  test("/v1/check does not send Authorization header", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ decision: "ALLOW", reason: "ok" })
    );
    const guard = new Vanzik({ apiKey: "secret-key" });
    await guard.check("shell", { command: "ls" });
    const [, init] = fetchMock.mock.calls[0];
    const headers = init?.headers as Record<string, string>;
    expect(headers.Authorization).toBeUndefined();
    expect(headers["Content-Type"]).toBe("application/json");
  });
});

// =========================================================================
// CheckResult getters
// =========================================================================

describe("CheckResult getters", () => {
  test("allowed is true only for ALLOW", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ decision: "ALLOW", reason: "ok" })
    );
    const guard = new Vanzik();
    const r: CheckResult = await guard.check("shell", { command: "ls" });
    expect(r.allowed).toBe(true);
    expect(r.denied).toBe(false);
    expect(r.needsApproval).toBe(false);
  });

  test("denied is true only for DENY", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ decision: "DENY", reason: "nope" })
    );
    const guard = new Vanzik();
    const r = await guard.check("shell", { command: "rm -rf /" });
    expect(r.allowed).toBe(false);
    expect(r.denied).toBe(true);
    expect(r.needsApproval).toBe(false);
  });

  test("needsApproval is true only for REQUIRE_APPROVAL", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        decision: "REQUIRE_APPROVAL",
        reason: "over threshold",
        approval_id: "ap_abc",
        approval_url: "http://localhost:8080/v1/approve/ap_abc",
      })
    );
    const guard = new Vanzik();
    const r = await guard.check("cost", { estCost: 99, sessionId: "s" });
    expect(r.needsApproval).toBe(true);
    expect(r.approvalId).toBe("ap_abc");
    expect(r.approvalUrl).toBe("http://localhost:8080/v1/approve/ap_abc");
  });
});

// =========================================================================
// Failure modes — unreachable Vanzik
// =========================================================================

describe("Vanzik.check failure modes", () => {
  test("default (failMode unset) denies on transport failure", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockRejectedValueOnce(new Error("ECONNREFUSED"));
    const guard = new Vanzik();
    const r = await guard.check("shell", { command: "ls" });
    expect(r.denied).toBe(true);
    expect(r.reason).toMatch(/Vanzik unreachable/);
  });

  test("failMode: 'allow' opens on transport failure", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockRejectedValueOnce(new Error("ECONNREFUSED"));
    const guard = new Vanzik({ failMode: "allow" });
    const r = await guard.check("shell", { command: "ls" });
    expect(r.allowed).toBe(true);
  });

  test("non-2xx response falls through to failMode", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(new Response("boom", { status: 500 }));
    const guard = new Vanzik();
    const r = await guard.check("shell", { command: "ls" });
    expect(r.denied).toBe(true);
    expect(r.reason).toMatch(/500/);
  });
});

// =========================================================================
// approve / deny / waitForApproval
// =========================================================================

describe("approval endpoints", () => {
  test("approve sends Bearer and returns ok status", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(new Response("", { status: 200 }));
    const guard = new Vanzik({ apiKey: "k" });
    const ok = await guard.approve("ap_1");
    expect(ok).toBe(true);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain("/v1/approve/ap_1");
    expect((init?.headers as Record<string, string>).Authorization).toBe("Bearer k");
    expect(init?.method).toBe("POST");
  });

  test("deny sends Bearer and returns ok status", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(new Response("", { status: 200 }));
    const guard = new Vanzik({ apiKey: "k" });
    const ok = await guard.deny("ap_1");
    expect(ok).toBe(true);
    const [url] = fetchMock.mock.calls[0];
    expect(String(url)).toContain("/v1/deny/ap_1");
  });

  test("waitForApproval resolves on ALLOW", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        id: "ap_1",
        status: "resolved",
        decision: "ALLOW",
        reason: "human said yes",
      })
    );
    const guard = new Vanzik({ apiKey: "k" });
    const r = await guard.waitForApproval("ap_1", 5000, 10);
    expect(r.allowed).toBe(true);
    // Every poll carries the Bearer header.
    const [, init] = fetchMock.mock.calls[0];
    expect((init?.headers as Record<string, string>).Authorization).toBe("Bearer k");
  });

  test("waitForApproval returns timeout DENY when deadline elapses", async () => {
    const fetchMock = installFetchMock();
    // Always pending.
    fetchMock.mockResolvedValue(
      jsonResponse({ id: "ap_1", status: "pending" })
    );
    const guard = new Vanzik();
    const r = await guard.waitForApproval("ap_1", 30, 5);
    expect(r.denied).toBe(true);
    expect(r.reason).toMatch(/timed out/i);
  });
});

// =========================================================================
// guarded() HOF
// =========================================================================

describe("guarded()", () => {
  // Wrapped fns here take `unknown[]` args and narrow inside the body;
  // strict_types.test.ts covers normally typed functions.
  type AnyAsyncFn = (...args: unknown[]) => Promise<unknown>;

  test("runs the wrapped fn when ALLOW", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ decision: "ALLOW", reason: "ok" })
    );
    const guard = new Vanzik();
    const fn = jest.fn(async (...args) => `ran ${String(args[0])}`);
    const safe = guarded(guard, "shell", fn as unknown as AnyAsyncFn);
    await expect(safe("ls")).resolves.toBe("ran ls");
    expect(fn).toHaveBeenCalledTimes(1);
  });

  test("throws on DENY without calling the wrapped fn", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ decision: "DENY", reason: "nope" })
    );
    const guard = new Vanzik();
    const fn = jest.fn(async () => "should not run");
    const safe = guarded(guard, "shell", fn as unknown as AnyAsyncFn);
    await expect(safe("rm -rf /")).rejects.toThrow(/denied by Vanzik/);
    expect(fn).not.toHaveBeenCalled();
  });

  test("throws on REQUIRE_APPROVAL by default", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        decision: "REQUIRE_APPROVAL",
        reason: "over threshold",
        approval_url: "http://localhost:8080/v1/approve/ap_abc",
      })
    );
    const guard = new Vanzik();
    const fn = jest.fn(async () => "should not run");
    const safe = guarded(guard, "cost", fn as unknown as AnyAsyncFn);
    await expect(safe("buy-a-car")).rejects.toThrow(/requires approval/);
    expect(fn).not.toHaveBeenCalled();
  });

  test("custom getCheckOptions is forwarded to check()", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ decision: "ALLOW", reason: "ok" })
    );
    const guard = new Vanzik();
    const fn = jest.fn(async () => "ran");
    const getOpts = (...args: unknown[]): CheckOptions => ({
      url: String(args[0]),
      sessionId: "s",
    });
    const safe = guarded(
      guard,
      "network",
      fn as unknown as AnyAsyncFn,
      getOpts as (...args: unknown[]) => CheckOptions
    );
    await safe("https://api.example");
    const body = parseBody(fetchMock.mock.calls[0][1]);
    expect(body).toMatchObject({
      scope: "network",
      url: "https://api.example",
      session_id: "s",
    });
  });
});

// =========================================================================
// Typed error classes
//
// All extend the built-in `Error`; callers narrow with `instanceof` and read
// structured fields (`result`, `approvalId`, `approvalUrl`).
// =========================================================================

describe("typed errors from guarded()", () => {
  type AnyAsyncFn = (...args: unknown[]) => Promise<unknown>;

  test("DENY throws VanzikDeniedError carrying the result", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        decision: "DENY",
        reason: "blocked",
        matched_rule: "deny:shell:rm",
      })
    );
    const guard = new Vanzik();
    const fn = jest.fn(async () => "should not run");
    const safe = guarded(guard, "shell", fn as unknown as AnyAsyncFn);

    let caught: unknown;
    try {
      await safe("rm -rf /");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(VanzikDeniedError);
    expect(caught).toBeInstanceOf(VanzikError);
    expect(caught).toBeInstanceOf(Error);
    const err = caught as VanzikDeniedError;
    expect(err.result?.denied).toBe(true);
    expect(err.result?.matchedRule).toBe("deny:shell:rm");
    expect(err.message).toMatch(/denied by Vanzik/);
  });

  test("REQUIRE_APPROVAL (default) throws VanzikApprovalRequiredError", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        decision: "REQUIRE_APPROVAL",
        reason: "over threshold",
        approval_id: "ap_abc",
        approval_url: "http://localhost:8080/v1/approve/ap_abc",
      })
    );
    const guard = new Vanzik();
    const fn = jest.fn(async () => "should not run");
    const safe = guarded(guard, "cost", fn as unknown as AnyAsyncFn);

    let caught: unknown;
    try {
      await safe("buy-a-car");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(VanzikApprovalRequiredError);
    const err = caught as VanzikApprovalRequiredError;
    expect(err.approvalId).toBe("ap_abc");
    expect(err.approvalUrl).toBe("http://localhost:8080/v1/approve/ap_abc");
    expect(err.result?.needsApproval).toBe(true);
    // Stable message text; caller code matches on it.
    expect(err.message).toMatch(/requires approval/);
  });

  test("all typed errors extend VanzikError (catchable uniformly)", () => {
    // Class-level invariants — cheaper than a full fetch-mock round-trip.
    expect(
      new VanzikDeniedError("x") instanceof VanzikError
    ).toBe(true);
    expect(
      new VanzikApprovalRequiredError("x") instanceof VanzikError
    ).toBe(true);
    expect(
      new VanzikApprovalTimeoutError("x") instanceof VanzikError
    ).toBe(true);
    expect(new VanzikError("x") instanceof Error).toBe(true);
  });
});

// =========================================================================
// guarded() with waitForApproval opt-in
// =========================================================================

describe("guarded() with waitForApproval", () => {
  type AnyAsyncFn = (...args: unknown[]) => Promise<unknown>;

  test("runs the wrapped fn when approval resolves ALLOW", async () => {
    const fetchMock = installFetchMock();
    // 1st call: /v1/check → REQUIRE_APPROVAL
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        decision: "REQUIRE_APPROVAL",
        reason: "needs review",
        approval_id: "ap_wait_ok",
        approval_url: "http://localhost:8080/v1/approve/ap_wait_ok",
      })
    );
    // 2nd call: /v1/status/ap_wait_ok → resolved ALLOW
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        id: "ap_wait_ok",
        status: "resolved",
        decision: "ALLOW",
        reason: "human approved",
      })
    );
    // 3rd call: the replay through /v1/check, which spends the one-shot
    // ALLOW (the status poll is read-only).
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ decision: "ALLOW", reason: "approved", matched_rule: "allow:approved" })
    );
    const guard = new Vanzik();
    const fn = jest.fn(async (...args) => `ran ${String(args[0])}`);
    const safe = guarded(guard, "shell", fn as unknown as AnyAsyncFn, {
      waitForApproval: true,
      approvalTimeoutMs: 2000,
      approvalPollIntervalMs: 5,
    });
    await expect(safe("deploy")).resolves.toBe("ran deploy");
    expect(fn).toHaveBeenCalledTimes(1);
    // The replay must carry the approval id, or the server never consumes it.
    expect(fetchMock).toHaveBeenCalledTimes(3);
    const replayBody = parseBody(fetchMock.mock.calls[2][1]);
    expect(replayBody.approval_id).toBe("ap_wait_ok");
  });

  test("throws VanzikDeniedError when approval resolves DENY", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        decision: "REQUIRE_APPROVAL",
        reason: "needs review",
        approval_id: "ap_wait_deny",
        approval_url: "http://localhost:8080/v1/approve/ap_wait_deny",
      })
    );
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        id: "ap_wait_deny",
        status: "resolved",
        decision: "DENY",
        reason: "human denied",
      })
    );
    const guard = new Vanzik();
    const fn = jest.fn(async () => "should not run");
    const safe = guarded(guard, "shell", fn as unknown as AnyAsyncFn, {
      waitForApproval: true,
      approvalTimeoutMs: 2000,
      approvalPollIntervalMs: 5,
    });

    let caught: unknown;
    try {
      await safe("deploy");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(VanzikDeniedError);
    expect((caught as VanzikDeniedError).message).toMatch(/human denied/);
    expect(fn).not.toHaveBeenCalled();
  });

  test("throws VanzikApprovalTimeoutError when approval never resolves", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        decision: "REQUIRE_APPROVAL",
        reason: "needs review",
        approval_id: "ap_wait_timeout",
        approval_url: "http://localhost:8080/v1/approve/ap_wait_timeout",
      })
    );
    // Every subsequent poll returns "pending"; waitForApproval returns its
    // synthetic "Approval timed out" DENY when the deadline elapses.
    fetchMock.mockResolvedValue(
      jsonResponse({ id: "ap_wait_timeout", status: "pending" })
    );
    const guard = new Vanzik();
    const fn = jest.fn(async () => "should not run");
    const safe = guarded(guard, "shell", fn as unknown as AnyAsyncFn, {
      waitForApproval: true,
      approvalTimeoutMs: 30,
      approvalPollIntervalMs: 5,
    });

    let caught: unknown;
    try {
      await safe("deploy");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(VanzikApprovalTimeoutError);
    const err = caught as VanzikApprovalTimeoutError;
    expect(err.approvalId).toBe("ap_wait_timeout");
    expect(err.message).toMatch(/timed out/i);
    expect(fn).not.toHaveBeenCalled();
  });
});
