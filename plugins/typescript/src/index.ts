/**
 * Vanzik TypeScript SDK
 *
 * Lightweight client for checking actions against Vanzik policies.
 *
 * @example
 * ```ts
 * import { Vanzik } from '@lictorate/vanzik';
 *
 * const guard = new Vanzik('http://localhost:8080');
 * const result = await guard.check('shell', { command: 'rm -rf ./data' });
 *
 * if (result.allowed) {
 *   execute(command);
 * } else if (result.needsApproval) {
 *   console.log(`Approve at: ${result.approvalUrl}`);
 * } else {
 *   console.log(`Blocked: ${result.reason}`);
 * }
 * ```
 */

export interface CheckOptions {
  action?: string;
  command?: string;
  path?: string;
  domain?: string;
  url?: string;
  /** Session identifier for session-level cost tracking. */
  sessionId?: string;
  /**
   * The session that started `sessionId` → request body
   * `parent_session_id`. Defaults to the client's `parentSessionId`.
   * Recorded in the audit log, not used by policy. Omitted when empty.
   */
  parentSessionId?: string;
  /** Estimated cost of this action in USD (for cost scope). */
  estCost?: number;
  meta?: Record<string, string>;
  /**
   * Replay of a previously issued approval → request body `approval_id`.
   *
   * Set it on the re-check after {@link Vanzik.waitForApproval} resolved
   * ALLOW, with the same scope and fields as the original request. The
   * replay, not the read-only `/v1/status` poll, consumes the one-shot
   * approval, enforces `--approval-validity`, reserves cost for cost-scoped
   * actions, and audits the execution as `allow:approved`. A refused replay
   * (consumed or expired) comes back as a fresh REQUIRE_APPROVAL under a
   * new id.
   */
  approvalId?: string;
}

export interface CheckResult {
  decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL";
  reason: string;
  matchedRule?: string;
  approvalId?: string;
  approvalUrl?: string;

  /** Convenience: true if decision is ALLOW */
  readonly allowed: boolean;
  /** Convenience: true if decision is DENY */
  readonly denied: boolean;
  /** Convenience: true if decision is REQUIRE_APPROVAL */
  readonly needsApproval: boolean;
}

/** Wire format of the /v1/check response; callers see `CheckResult`. */
interface CheckResponseJSON {
  decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL";
  reason: string;
  matched_rule?: string;
  approval_id?: string;
  approval_url?: string;
}

/** Wire-format of the /v1/status/{id} response. */
interface StatusResponseJSON {
  id: string;
  status: "pending" | "resolved";
  decision?: "ALLOW" | "DENY";
  reason?: string;
}

export interface VanzikOptions {
  /** Base URL of the Vanzik server (default: http://localhost:8080) */
  baseUrl?: string;
  /** Agent identifier sent with every check */
  agentId?: string;
  /** API key for authenticated endpoints (approve/deny) */
  apiKey?: string;
  /** Request timeout in milliseconds (default: 5000) */
  timeout?: number;
  /** Behavior when Vanzik is unreachable: 'deny' (default) or 'allow' */
  failMode?: "deny" | "allow";
  /**
   * Optional tenant identifier. A non-empty value other than `"local"`
   * routes every call through `/v1/t/{tenantId}/...` instead of the legacy
   * `/v1/...` URLs. Falls back to `VANZIK_TENANT_ID` (Node only). The
   * bundled FilePolicyProvider only recognises `"local"`; multi-tenant
   * providers can register others.
   */
  tenantId?: string;
  /**
   * The session that started this agent's sessions, e.g. the
   * orchestrator's session for a sub-agent. Sent as `parent_session_id`
   * on every check (a per-call `parentSessionId` wins). Policy ignores
   * it; the audit log records it so `GET /v1/sessions` can link parent
   * and child sessions.
   */
  parentSessionId?: string;
}

/** Tenant value that selects the legacy (single-tenant) URL family. */
export const LOCAL_TENANT_ID = "local";

/**
 * Read a process.env variable without assuming Node: undefined when the
 * runtime has no `process` (browsers, Deno without --compat) or the
 * variable is unset or empty.
 */
function readEnv(name: string): string | undefined {
  try {
    const p = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
    const v = p && p.env ? p.env[name] : undefined;
    return v && v.length > 0 ? v : undefined;
  } catch {
    return undefined;
  }
}

const MIGRATION_URL =
  "https://github.com/lictorate/vanzik/blob/master/docs/MIGRATION.md#v1x-to-v20";

/**
 * `VANZIK_<name>` from the environment, or undefined. `AGENTGUARD_<name>`
 * (the variable's name before Vanzik 2.0) is never read: when it is set
 * and `VANZIK_<name>` is not, this throws instead of falling back, since a
 * client that ignored it would send no API key, or check calls against
 * another server or tenant's policy, without saying so.
 */
function fromEnv(name: string): string | undefined {
  const value = readEnv("VANZIK_" + name);
  if (value === undefined && readEnv("AGENTGUARD_" + name) !== undefined) {
    throw new TypeError(
      `Vanzik: AGENTGUARD_${name} is set, but Vanzik reads VANZIK_${name}: ` +
        `rename the variable (see ${MIGRATION_URL}).`
    );
  }
  return value;
}

class CheckResultImpl implements CheckResult {
  decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL";
  reason: string;
  matchedRule?: string;
  approvalId?: string;
  approvalUrl?: string;

  constructor(data: Partial<CheckResult>) {
    this.decision = data.decision ?? "DENY";
    this.reason = data.reason ?? "";
    this.matchedRule = data.matchedRule;
    this.approvalId = data.approvalId;
    this.approvalUrl = data.approvalUrl;
  }

  get allowed(): boolean {
    return this.decision === "ALLOW";
  }
  get denied(): boolean {
    return this.decision === "DENY";
  }
  get needsApproval(): boolean {
    return this.decision === "REQUIRE_APPROVAL";
  }
}

/**
 * Base class for Vanzik policy-failure errors thrown by {@link guarded}.
 * Subclasses carry structured fields (`result`, `approvalId`,
 * `approvalUrl`) for `instanceof` checks.
 */
export class VanzikError extends Error {
  readonly result?: CheckResult;

  constructor(message: string, result?: CheckResult) {
    super(message);
    this.name = "VanzikError";
    this.result = result;
    // Fix instanceof across downstream transpile targets (ES5).
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Thrown when the policy decision was DENY. */
export class VanzikDeniedError extends VanzikError {
  constructor(message: string, result?: CheckResult) {
    super(message, result);
    this.name = "VanzikDeniedError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when the policy decision was REQUIRE_APPROVAL and the
 * decorator/HOF was not configured to wait for resolution.
 */
export class VanzikApprovalRequiredError extends VanzikError {
  readonly approvalId: string;
  readonly approvalUrl: string;

  constructor(
    message: string,
    result?: CheckResult,
    approvalId = "",
    approvalUrl = ""
  ) {
    super(message, result);
    this.name = "VanzikApprovalRequiredError";
    this.approvalId = approvalId;
    this.approvalUrl = approvalUrl;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when `waitForApproval` was requested but the action did not resolve
 * before the deadline. `result` carries the synthetic DENY/"Approval timed
 * out" produced by {@link Vanzik.waitForApproval}.
 */
export class VanzikApprovalTimeoutError extends VanzikError {
  readonly approvalId: string;

  constructor(message: string, result?: CheckResult, approvalId = "") {
    super(message, result);
    this.name = "VanzikApprovalTimeoutError";
    this.approvalId = approvalId;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when an auth-gated Vanzik endpoint (`/v1/approve`,
 * `/v1/deny`, `/v1/status`, `/v1/audit`) returns 401 or 403, so a wrong
 * or expired API key is not mistaken for an approval timeout.
 */
export class VanzikAuthError extends VanzikError {
  readonly status: number;

  constructor(message: string, status: number, result?: CheckResult) {
    super(message, result);
    this.name = "VanzikAuthError";
    this.status = status;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Valid values for the `failMode` option. */
const VALID_FAIL_MODES = ["deny", "allow"] as const;

/**
 * Allowed keys on `VanzikOptions`. Unknown keys throw at construction, so
 * a typo like `agnetId: "x"` fails loudly instead of running with
 * `agentId = ""`.
 */
const VALID_VANZIK_OPTION_KEYS: ReadonlySet<string> = new Set([
  "baseUrl",
  "agentId",
  "apiKey",
  "timeout",
  "failMode",
  "tenantId",
  "parentSessionId",
]);

/**
 * Allowed keys on the {@link guarded} options object.
 */
const VALID_GUARDED_OPTION_KEYS: ReadonlySet<string> = new Set([
  "getCheckOptions",
  "waitForApproval",
  "approvalTimeoutMs",
  "approvalPollIntervalMs",
]);

export class Vanzik {
  private baseUrl: string;
  private agentId: string;
  private apiKey: string;
  private timeout: number;
  private failMode: "deny" | "allow";
  private tenantId: string;
  private parentSessionId: string;

  constructor(baseUrlOrOptions?: string | VanzikOptions) {
    // VANZIK_URL / VANZIK_API_KEY / VANZIK_TENANT_ID are read only for
    // settings the caller left out (as in the Python SDK), so a stale
    // AGENTGUARD_* variable matters only where it would have been used.
    if (typeof baseUrlOrOptions === "string") {
      this.baseUrl = baseUrlOrOptions.replace(/\/$/, "");
      this.agentId = "";
      this.apiKey = fromEnv("API_KEY") ?? "";
      this.timeout = 5000;
      this.failMode = "deny";
      this.tenantId = fromEnv("TENANT_ID") ?? "";
      this.parentSessionId = "";
    } else {
      const opts = baseUrlOrOptions ?? {};

      const unknown = Object.keys(opts).filter(
        (k) => !VALID_VANZIK_OPTION_KEYS.has(k)
      );
      if (unknown.length > 0) {
        throw new TypeError(
          `Vanzik: unknown options ${JSON.stringify(unknown)}. ` +
            `Valid options: ${JSON.stringify(
              Array.from(VALID_VANZIK_OPTION_KEYS).sort()
            )}.`
        );
      }

      this.baseUrl = (opts.baseUrl ?? fromEnv("URL") ?? "http://localhost:8080").replace(
        /\/$/,
        ""
      );
      this.agentId = opts.agentId ?? "";
      this.apiKey = opts.apiKey ?? fromEnv("API_KEY") ?? "";
      this.timeout = opts.timeout ?? 5000;
      this.failMode = opts.failMode ?? "deny";
      // An explicit tenantId, even "", wins over the env var: "" is the
      // supported way to suppress a leaked VANZIK_TENANT_ID.
      this.tenantId = opts.tenantId !== undefined ? opts.tenantId : fromEnv("TENANT_ID") ?? "";
      this.parentSessionId = opts.parentSessionId ?? "";
    }

    // A bad failMode (typo, boolean, "DENY") must fail at startup, not at
    // the first request.
    if (
      !(VALID_FAIL_MODES as readonly string[]).includes(this.failMode)
    ) {
      throw new TypeError(
        `Vanzik: invalid failMode ${JSON.stringify(this.failMode)}. ` +
          `Expected one of ${JSON.stringify(VALID_FAIL_MODES)}.`
      );
    }
  }

  /**
   * Build the absolute URL for the given /v1 suffix.
   *
   * `suffix` is the path *after* `/v1`, e.g. `"/check"`,
   * `"/approve/ap_abc"`, `"/audit"`. When `tenantId` is set and not
   * `"local"`, the URL becomes `{baseUrl}/v1/t/{tenantId}{suffix}` with
   * `tenantId` URL-encoded via `encodeURIComponent` so reserved chars
   * (`/`, spaces) cannot break the path layout.
   */
  private url(suffix: string): string {
    if (this.tenantId && this.tenantId !== LOCAL_TENANT_ID) {
      return `${this.baseUrl}/v1/t/${encodeURIComponent(this.tenantId)}${suffix}`;
    }
    return `${this.baseUrl}/v1${suffix}`;
  }

  private authHeaders(): Record<string, string> {
    if (this.apiKey) {
      return { Authorization: `Bearer ${this.apiKey}` };
    }
    return {};
  }

  /**
   * `fetch` with the client timeout applied to the WHOLE exchange — connect,
   * headers, **and** the body read performed by `consume`. Clearing the
   * timer when the headers arrive would let a server that stalls mid-body
   * hang the calling agent forever.
   */
  private async withTimeout<T>(
    url: string,
    init: RequestInit,
    consume: (res: Response) => Promise<T>
  ): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(url, { ...init, signal: controller.signal });
      return await consume(res);
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Check an action against the Vanzik policy.
   */
  async check(scope: string, options: CheckOptions = {}): Promise<CheckResult> {
    const payload: Record<string, unknown> = {
      scope,
      agent_id: this.agentId,
    };

    if (options.action) payload.action = options.action;
    if (options.command) payload.command = options.command;
    if (options.path) payload.path = options.path;
    if (options.domain) payload.domain = options.domain;
    if (options.url) payload.url = options.url;
    if (options.sessionId) payload.session_id = options.sessionId;
    if (options.estCost !== undefined && options.estCost !== 0) payload.est_cost = options.estCost;
    if (options.meta) payload.meta = options.meta;
    if (options.approvalId) payload.approval_id = options.approvalId;
    const parentSessionId = options.parentSessionId || this.parentSessionId;
    if (parentSessionId) payload.parent_session_id = parentSessionId;

    try {
      return await this.withTimeout(
        this.url("/check"),
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        },
        async (response) => {
          // Positively assert status, content type and a `decision` field:
          // a misconfigured reverse proxy can return HTML, or JSON that
          // parses but lacks `decision`.
          if (!response.ok) {
            return this.failModeResult(
              `Vanzik returned status ${response.status}`
            );
          }

          const ctype = (response.headers.get("Content-Type") ?? "").toLowerCase();
          if (!ctype.startsWith("application/json")) {
            return this.failModeResult(
              `Vanzik returned unexpected content-type ${JSON.stringify(ctype)}`
            );
          }

          let raw: unknown;
          try {
            raw = await response.json();
          } catch (e) {
            return this.failModeResult(
              `Vanzik returned non-JSON body: ${
                e instanceof Error ? e.message : String(e)
              }`
            );
          }

          if (
            raw === null ||
            typeof raw !== "object" ||
            typeof (raw as { decision?: unknown }).decision !== "string"
          ) {
            return this.failModeResult(
              `Vanzik returned malformed response body (missing 'decision')`
            );
          }

          const data = raw as CheckResponseJSON;
          return new CheckResultImpl({
            decision: data.decision,
            reason: data.reason,
            matchedRule: data.matched_rule,
            approvalId: data.approval_id,
            approvalUrl: data.approval_url,
          });
        }
      );
    } catch (err) {
      // Fail closed (deny) by default when Vanzik is unreachable.
      return this.failModeResult(
        `Vanzik unreachable: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  /** Build a CheckResult honoring the configured `failMode`. */
  private failModeResult(reason: string): CheckResult {
    const fallbackDecision = this.failMode === "allow" ? "ALLOW" : "DENY";
    return new CheckResultImpl({
      decision: fallbackDecision,
      reason,
    });
  }

  /**
   * Approve a pending action.
   */
  async approve(approvalId: string): Promise<boolean> {
    try {
      return await this.withTimeout(
        this.url(`/approve/${approvalId}`),
        { method: "POST", headers: this.authHeaders() },
        async (res) => res.ok
      );
    } catch {
      return false;
    }
  }

  /**
   * Deny a pending action.
   */
  async deny(approvalId: string): Promise<boolean> {
    try {
      return await this.withTimeout(
        this.url(`/deny/${approvalId}`),
        { method: "POST", headers: this.authHeaders() },
        async (res) => res.ok
      );
    } catch {
      return false;
    }
  }

  /**
   * Wait for a pending action to be resolved (blocks).
   *
   * Sends the API key on every poll since /v1/status is auth-gated on
   * servers configured with --api-key.
   */
  async waitForApproval(
    approvalId: string,
    timeoutMs: number = 300_000,
    pollIntervalMs: number = 2_000
  ): Promise<CheckResult> {
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      try {
        const resolved = await this.withTimeout(
          this.url(`/status/${approvalId}`),
          { headers: this.authHeaders() },
          async (res) => {
            // A broken API key must not end as a timeout DENY that hides it.
            if (res.status === 401 || res.status === 403) {
              throw new VanzikAuthError(
                `Vanzik rejected status poll for ${approvalId} ` +
                  `with HTTP ${res.status} (check apiKey)`,
                res.status
              );
            }
            if (!res.ok) return undefined;
            const data = (await res.json()) as StatusResponseJSON;
            if (data.status === "resolved" && (data.decision === "ALLOW" || data.decision === "DENY")) {
              return new CheckResultImpl({
                decision: data.decision,
                reason: data.reason ?? "resolved",
              });
            }
            return undefined;
          }
        );
        if (resolved) return resolved;
      } catch (e) {
        // Everything but VanzikAuthError (DNS, ECONNREFUSED, a per-poll
        // timeout, a non-JSON body) is retried until the deadline; a
        // malformed poll body must never reject out of the waiting agent.
        if (e instanceof VanzikAuthError) throw e;
      }

      // 80%..120% jitter so many clients waiting on one approval don't
      // poll in lockstep.
      const jitter = pollIntervalMs * (0.8 + 0.4 * Math.random());
      await new Promise((resolve) => setTimeout(resolve, jitter));
    }

    return new CheckResultImpl({
      decision: "DENY",
      reason: "Approval timed out",
    });
  }
}

/**
 * Optional configuration for {@link guarded}.
 *
 * `waitForApproval: true` dispatches on the resolved decision instead of
 * throwing immediately on REQUIRE_APPROVAL — mirrors the Python SDK's
 * `wait_for_approval=True`.
 */
export interface GuardedOptions<T extends (...args: any[]) => Promise<any>> {
  /** Custom extractor for the `CheckOptions` payload from the wrapped function's args. */
  getCheckOptions?: (...args: Parameters<T>) => CheckOptions;
  /** Block until a human approves/denies when the decision is REQUIRE_APPROVAL. Default false. */
  waitForApproval?: boolean;
  /** Total time to wait for a resolution, in ms. Default 300_000. */
  approvalTimeoutMs?: number;
  /** Poll interval while waiting, in ms. Default 2_000. */
  approvalPollIntervalMs?: number;
}

/**
 * Higher-order function that wraps an async function with a Vanzik check.
 *
 * Two overloads: callers can pass a fourth positional `getCheckOptions`
 * callback, or a typed options object that adds `waitForApproval`,
 * `approvalTimeoutMs`, `approvalPollIntervalMs`.
 *
 * @example
 * ```ts
 * const guard = new Vanzik('http://localhost:8080');
 * const safeExec = guarded(guard, 'shell', (cmd: string) => exec(cmd));
 *
 * await safeExec('ls -la');        // Allowed → runs
 * await safeExec('rm -rf /');      // DENY → throws VanzikDeniedError
 *
 * // Opt-in: block until a human approves.
 * const reviewed = guarded(guard, 'shell', (cmd: string) => exec(cmd), {
 *   waitForApproval: true,
 *   approvalTimeoutMs: 60_000,
 * });
 * ```
 */
export function guarded<T extends (...args: any[]) => Promise<any>>(
  guard: Vanzik,
  scope: string,
  fn: T,
  getCheckOptions?: (...args: Parameters<T>) => CheckOptions
): T;
export function guarded<T extends (...args: any[]) => Promise<any>>(
  guard: Vanzik,
  scope: string,
  fn: T,
  options: GuardedOptions<T>
): T;
export function guarded<T extends (...args: any[]) => Promise<any>>(
  guard: Vanzik,
  scope: string,
  fn: T,
  optionsOrGetCheckOptions?:
    | ((...args: Parameters<T>) => CheckOptions)
    | GuardedOptions<T>
): T {
  // Normalize the overload — a bare callback is the simple shape.
  const opts: GuardedOptions<T> =
    typeof optionsOrGetCheckOptions === "function"
      ? { getCheckOptions: optionsOrGetCheckOptions }
      : optionsOrGetCheckOptions ?? {};

  // A typo such as `waitForApprovel: true` must not be silently ignored.
  const unknownGuardedKeys = Object.keys(opts).filter(
    (k) => !VALID_GUARDED_OPTION_KEYS.has(k)
  );
  if (unknownGuardedKeys.length > 0) {
    throw new TypeError(
      `guarded(): unknown option ${JSON.stringify(unknownGuardedKeys)}. ` +
        `Valid options: ${JSON.stringify(
          Array.from(VALID_GUARDED_OPTION_KEYS).sort()
        )}.`
    );
  }

  const waitForApproval = opts.waitForApproval ?? false;
  const approvalTimeoutMs = opts.approvalTimeoutMs ?? 300_000;
  const approvalPollIntervalMs = opts.approvalPollIntervalMs ?? 2_000;
  const getCheckOptions = opts.getCheckOptions;

  return (async (...args: Parameters<T>) => {
    const options = getCheckOptions
      ? getCheckOptions(...args)
      : { command: String(args[0] ?? "") };

    const result = await guard.check(scope, options);

    if (result.allowed) {
      return fn(...args);
    }

    if (result.needsApproval) {
      if (waitForApproval) {
        const resolved = await guard.waitForApproval(
          result.approvalId ?? "",
          approvalTimeoutMs,
          approvalPollIntervalMs
        );
        if (resolved.allowed) {
          // The status poll is read-only; only this replay spends the
          // one-shot approval.
          const replay = await guard.check(scope, {
            ...options,
            approvalId: result.approvalId ?? "",
          });
          if (replay.allowed) {
            return fn(...args);
          }
          if (replay.needsApproval) {
            // Consumed or expired, re-issued under a new id. Don't wait
            // again: a refused replay would loop forever.
            throw new VanzikApprovalRequiredError(
              `Action requires approval. Approve at: ${replay.approvalUrl}`,
              replay,
              replay.approvalId ?? "",
              replay.approvalUrl ?? ""
            );
          }
          throw new VanzikDeniedError(
            `Action denied by Vanzik: ${replay.reason}`,
            replay
          );
        }
        if (resolved.denied && resolved.reason === "Approval timed out") {
          throw new VanzikApprovalTimeoutError(
            `Approval for ${result.approvalId ?? ""} timed out after ${approvalTimeoutMs}ms`,
            resolved,
            result.approvalId ?? ""
          );
        }
        throw new VanzikDeniedError(
          `Action denied by Vanzik: ${resolved.reason}`,
          resolved
        );
      }
      // Stable message text — text-matchers in caller code depend on it.
      throw new VanzikApprovalRequiredError(
        `Action requires approval. Approve at: ${result.approvalUrl}`,
        result,
        result.approvalId ?? "",
        result.approvalUrl ?? ""
      );
    }

    throw new VanzikDeniedError(
      `Action denied by Vanzik: ${result.reason}`,
      result
    );
  }) as T;
}

export default Vanzik;
