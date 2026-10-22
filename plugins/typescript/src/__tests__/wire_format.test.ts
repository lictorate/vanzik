/**
 * Cross-language wire-protocol contract test (TypeScript side).
 *
 * The Go and Python siblings live at:
 *   - pkg/proxy/schema/v1/types_test.go
 *   - plugins/python/tests/test_wire_format.py
 *
 * All three load the same fixtures from
 *   pkg/proxy/schema/v1/testdata/sample_request.json
 *   pkg/proxy/schema/v1/testdata/sample_result.json
 * and assert that the JSON shape produced/consumed by each SDK matches
 * the canonical v1 schema.
 *
 * The file sits under src/__tests__ because jest.config.js only scans
 * plugins/typescript/src.
 */

import * as fs from "fs";
import * as path from "path";

import { Vanzik } from "../index";
import type { CheckOptions } from "../index";

// ---------------------------------------------------------------------------
// Fixture path resolution
// ---------------------------------------------------------------------------

// __dirname is <repo>/plugins/typescript/src/__tests__.
const REPO_ROOT = path.resolve(__dirname, "..", "..", "..", "..");
const FIXTURES_DIR = path.join(REPO_ROOT, "pkg", "proxy", "schema", "v1", "testdata");

function loadFixture(name: string): Record<string, unknown> {
  const p = path.join(FIXTURES_DIR, name);
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

// ---------------------------------------------------------------------------
// Fetch mock plumbing
// ---------------------------------------------------------------------------

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

function parseBody(init: RequestInit | undefined): Record<string, unknown> {
  if (!init || typeof init.body !== "string") return {};
  return JSON.parse(init.body as string) as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Allowed wire-format keys (subset of the v1 ActionRequest schema).
// ---------------------------------------------------------------------------

const WIRE_KEYS_REQUIRED = new Set<string>(["scope"]);
const WIRE_KEYS_OPTIONAL = new Set<string>([
  "schema_version",
  "action",
  "command",
  "path",
  "domain",
  "url",
  "agent_id",
  "session_id",
  "est_cost",
  "meta",
]);
const WIRE_KEYS_ALLOWED = new Set<string>([
  ...WIRE_KEYS_REQUIRED,
  ...WIRE_KEYS_OPTIONAL,
]);

// =========================================================================
// Fixture sanity checks
// =========================================================================

describe("v1 wire-protocol fixtures", () => {
  test("sample_request.json exists and decodes", () => {
    expect(fs.existsSync(path.join(FIXTURES_DIR, "sample_request.json"))).toBe(true);
    const body = loadFixture("sample_request.json");
    expect(body).toEqual({
      schema_version: "v1",
      agent_id: "test-agent-001",
      session_id: "sess-abc",
      scope: "shell",
      command: "ls -la",
      meta: { source: "ci-fixture" },
    });
  });

  test("sample_result.json exists and decodes", () => {
    expect(fs.existsSync(path.join(FIXTURES_DIR, "sample_result.json"))).toBe(true);
    const body = loadFixture("sample_result.json");
    expect(body).toEqual({
      schema_version: "v1",
      decision: "ALLOW",
      reason: "matched allow rule",
      matched_rule: "allow:shell:ls",
    });
  });
});

// =========================================================================
// Request-builder contract: the SDK must emit a body whose key set is a
// subset of the v1 schema.
// =========================================================================

describe("Vanzik.check wire format", () => {
  test("emitted body is a v1 ActionRequest subset", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse(loadFixture("sample_result.json"))
    );

    const guard = new Vanzik({
      baseUrl: "http://example.invalid",
      agentId: "test-agent-001",
    });
    const opts: CheckOptions = {
      command: "ls -la",
      sessionId: "sess-abc",
      meta: { source: "ci-fixture" },
    };
    await guard.check("shell", opts);

    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("http://example.invalid/v1/check");
    expect(init?.method).toBe("POST");

    const body = parseBody(init);
    const keys = Object.keys(body);

    for (const k of keys) {
      expect(WIRE_KEYS_ALLOWED.has(k)).toBe(true);
    }

    for (const required of WIRE_KEYS_REQUIRED) {
      expect(keys).toContain(required);
    }
  });

  test("emitted body matches cross-language fixture (modulo schema_version)", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse(loadFixture("sample_result.json"))
    );

    const guard = new Vanzik({
      baseUrl: "http://example.invalid",
      agentId: "test-agent-001",
    });
    await guard.check("shell", {
      command: "ls -la",
      sessionId: "sess-abc",
      meta: { source: "ci-fixture" },
    });

    const [, init] = fetchMock.mock.calls[0];
    const body = parseBody(init);

    // The SDK does not emit schema_version (the server defaults it to
    // "v1"), so it is stripped from the fixture. If the SDK starts emitting
    // it, drop the strip.
    const fixture = loadFixture("sample_request.json") as Record<string, unknown>;
    const { schema_version: _ignored, ...expected } = fixture;
    void _ignored;
    expect(body).toEqual(expected);
  });

  test("uses snake_case field names exclusively", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse(loadFixture("sample_result.json"))
    );

    const guard = new Vanzik({ agentId: "x" });
    await guard.check("cost", {
      sessionId: "sess-x",
      estCost: 0.05,
      command: "expensive_op",
    });

    const [, init] = fetchMock.mock.calls[0];
    const body = parseBody(init);
    // camelCase leaking to the wire would silently bypass the server's
    // session_id / est_cost handling.
    const forbidden = ["sessionId", "estCost", "agentId"];
    for (const k of forbidden) {
      expect(Object.keys(body)).not.toContain(k);
    }
    expect(body.session_id).toBe("sess-x");
    expect(body.est_cost).toBe(0.05);
    expect(body.agent_id).toBe("x");
  });

  test("omits est_cost when zero", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse(loadFixture("sample_result.json"))
    );

    const guard = new Vanzik({ agentId: "x" });
    await guard.check("shell", { command: "ls", estCost: 0 });

    const [, init] = fetchMock.mock.calls[0];
    const body = parseBody(init);
    expect(body).not.toHaveProperty("est_cost");
  });
});

// =========================================================================
// Response decoder: every v1 result must round-trip through the SDK.
// =========================================================================

describe("Vanzik.check response decoding", () => {
  test.each(["ALLOW", "DENY", "REQUIRE_APPROVAL"] as const)(
    "decodes %s decision from a v1-shaped response",
    async (decision) => {
      const fetchMock = installFetchMock();
      fetchMock.mockResolvedValueOnce(
        jsonResponse({
          schema_version: "v1",
          decision,
          reason: "test",
        })
      );

      const guard = new Vanzik({ agentId: "x" });
      const result = await guard.check("shell", { command: "ls" });
      expect(result.decision).toBe(decision);
    }
  );

  test("decodes the cross-language result fixture", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse(loadFixture("sample_result.json"))
    );

    const guard = new Vanzik({ agentId: "x" });
    const result = await guard.check("shell", { command: "ls -la" });
    expect(result.allowed).toBe(true);
    expect(result.decision).toBe("ALLOW");
    expect(result.reason).toBe("matched allow rule");
    expect(result.matchedRule).toBe("allow:shell:ls");
  });

  test("tolerates a v1.x response with unknown additive fields", async () => {
    const fetchMock = installFetchMock();
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        schema_version: "v1",
        decision: "ALLOW",
        reason: "ok",
        matched_rule: "allow:shell:ls",
        // Forward-compat: a future v1.x server may add fields. The
        // SDK must ignore them rather than crash.
        policy_revision: "abc123",
      })
    );

    const guard = new Vanzik({ agentId: "x" });
    const result = await guard.check("shell", { command: "ls" });
    expect(result.allowed).toBe(true);
    expect(result.matchedRule).toBe("allow:shell:ls");
  });
});
