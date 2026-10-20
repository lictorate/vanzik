/**
 * The AGENTGUARD_* variables the SDK read before Vanzik 2.0.
 *
 * Mirrors plugins/python/tests/test_legacy_env.py: they are never read, and
 * a client that would have fallen back to one throws instead of running
 * without it. An explicit option, or the VANZIK_* variable, makes the old
 * one irrelevant.
 */

import { Vanzik } from "../index";

const NAMES = ["URL", "API_KEY", "TENANT_ID"];

describe("AGENTGUARD_* variables", () => {
  const saved: Record<string, string | undefined> = {};

  beforeEach(() => {
    for (const n of NAMES) {
      for (const v of ["VANZIK_" + n, "AGENTGUARD_" + n]) {
        saved[v] = process.env[v];
        delete process.env[v];
      }
    }
  });

  afterEach(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

  it.each(NAMES)("AGENTGUARD_%s alone throws, naming VANZIK_*", (name) => {
    process.env["AGENTGUARD_" + name] = "old";
    expect(() => new Vanzik()).toThrow("VANZIK_" + name);
  });

  it("explicit options make the old variables irrelevant", () => {
    for (const n of NAMES) process.env["AGENTGUARD_" + n] = "old";
    expect(
      () => new Vanzik({ baseUrl: "http://new:8080", apiKey: "k", tenantId: "acme" })
    ).not.toThrow();
  });

  it("the VANZIK_* variable wins", () => {
    for (const n of NAMES) {
      process.env["AGENTGUARD_" + n] = "old";
      process.env["VANZIK_" + n] = "http://new:8080";
    }
    expect(() => new Vanzik()).not.toThrow();
  });
});
