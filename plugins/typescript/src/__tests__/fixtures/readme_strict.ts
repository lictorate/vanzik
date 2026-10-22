/**
 * Type-check fixture: the README's `guarded` and fail-mode examples, as
 * written, with no casts. strict_types.test.ts compiles this file under
 * `strict`; it is never executed.
 */

import { Vanzik, guarded, VanzikDeniedError } from "../../index";

declare function exec(cmd: string): Promise<string>;
declare function makeExpensiveCall(prompt: string, maxTokens: number): Promise<string>;

// Fail mode
// Default: fail closed.
const strictGuard = new Vanzik("http://localhost:8080");
// Opt-in: fail open.
const advisoryGuard = new Vanzik({ baseUrl: "http://localhost:8080", failMode: "allow" });

export async function readmeExamples(): Promise<void> {
  const guard = new Vanzik("http://localhost:8080");

  const safeExec = guarded(guard, "shell",
    async (cmd: string) => exec(cmd));

  await safeExec("ls -la");
  try {
    await safeExec("dd if=/dev/zero of=/dev/sda");
  } catch (e) {
    if (e instanceof VanzikDeniedError) {
      console.log(e.result?.matchedRule);
    }
  }

  // Custom extractor
  const safeFetch = guarded(
    guard,
    "network",
    async (url: string) => fetch(url),
    (url) => ({ url, domain: new URL(url).hostname }),
  );

  // Opt-in: block until human approves on REQUIRE_APPROVAL
  const reviewed = guarded(guard, "cost", makeExpensiveCall, {
    waitForApproval: true,
    approvalTimeoutMs: 60_000,
  });

  // The wrapper keeps the wrapped function's signature.
  const out: string = await safeExec("ls");
  const res: Response = await safeFetch("https://example.com");
  const text: string = await reviewed("hi", 100);
  // @ts-expect-error wrong argument type is still rejected
  await safeExec(42);
  // @ts-expect-error missing argument is still rejected
  await reviewed("hi");
  void [out, res, text, strictGuard, advisoryGuard];
}
