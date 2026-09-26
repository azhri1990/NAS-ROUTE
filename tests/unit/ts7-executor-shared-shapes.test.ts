import { describe, it } from "node:test";
import assert from "node:assert/strict";

const { OpencodeExecutor } = await import("../../open-sse/executors/opencode.ts");
const { getEffectiveToolLimit } = await import("../../open-sse/services/toolLimitDetector.ts");
const { MAX_TOOLS_LIMIT } = await import("../../open-sse/config/constants.ts");

/**
 * Behavioral guards for the three type-only fixes in the TS 7 executor slice
 * (see #8484). Each fix restored a type the code already depended on at runtime;
 * these tests pin the runtime contracts so a future "simplification" of the
 * annotations cannot silently change behavior.
 *
 * The zed-hosted `SseEnqueueTarget` fix is already covered end-to-end by
 * `zed-hosted-think-close-marker.test.ts`, which drives the same TransformStream
 * that failed to type-check — no duplicate added here.
 *
 * Tool-list capping is NOT one of those contracts. This file used to assert a
 * hardcoded `slice(0, 128)` inside `transformRequest`; that cap was deliberately
 * removed in #11444 because it silently dropped every tool past the 128th and
 * left subagent tasks paralyzed. The 128 limit is real, but it belongs to
 * `chatCore upstreamBody.truncateToolList()` — see the two tests below, which pin
 * the delegation and the central limit instead of resurrecting the removed cap.
 */

describe("OpencodeExecutor — tool-list handling survives the narrowing fix", () => {
  const executor = new OpencodeExecutor("opencode-go");
  const CREDENTIALS = { apiKey: "k" } as Record<string, unknown>;

  const tools = (n: number) =>
    Array.from({ length: n }, (_, i) => ({
      type: "function",
      function: { name: `tool_${i}`, parameters: {} },
    }));

  function bodyWith(toolCount: number) {
    return {
      model: "oc/kimi-k2.6",
      stream: true,
      messages: [{ role: "user", content: "hi" }],
      tools: tools(toolCount),
    };
  }

  it("forwards an over-long tools array intact instead of capping it here (#11444)", () => {
    const out = executor.transformRequest("oc/kimi-k2.6", bodyWith(200), true, CREDENTIALS) as {
      tools: unknown[];
    };
    assert.equal(out.tools.length, 200, "executor must forward all 200 tools untouched");
    assert.equal(
      (out.tools[199] as { function: { name: string } }).function.name,
      "tool_199",
      "the 200th tool must survive — dropping it is exactly the #11444 bug"
    );
  });

  it("still enforces the 128 cap centrally, via the shared tool-limit detector", () => {
    // The concern behind the old assertion was legitimate: opencode upstreams
    // reject more than MAX_TOOLS_LIMIT tools. That cap is applied in chatCore's
    // upstreamBody.truncateToolList(), so pin it there. This keeps the limit from
    // being silently removed while still honouring `bypassDefaultToolLimit` and
    // runtime-detected per-provider limits, both of which an executor-level
    // hardcoded slice bypassed. Full executor matrix: opencode-tools-no-truncation.test.ts
    assert.equal(MAX_TOOLS_LIMIT, 128, "the shared default cap is 128 tools");
    assert.equal(
      getEffectiveToolLimit("opencode-go"),
      MAX_TOOLS_LIMIT,
      "opencode-go has no provider-specific entry, so the shared 128 cap applies"
    );
  });

  it("leaves a within-limit tools array untouched", () => {
    const out = executor.transformRequest("oc/kimi-k2.6", bodyWith(10), true, CREDENTIALS) as {
      tools: unknown[];
    };
    assert.equal(out.tools.length, 10);
  });

  it("is a no-op when the body carries no tools", () => {
    const body = {
      model: "oc/kimi-k2.6",
      stream: true,
      messages: [{ role: "user", content: "hi" }],
    };
    const out = executor.transformRequest("oc/kimi-k2.6", body, true, CREDENTIALS) as Record<
      string,
      unknown
    >;
    assert.equal("tools" in out, false);
    assert.ok(Array.isArray(out.messages), "messages preserved");
  });

  it("leaves an array-shaped body alone (pins the !Array.isArray guard)", () => {
    // The pre-fix condition reached `.tools` on any object, arrays included, and
    // relied on `Array.isArray(undefined)` short-circuiting. The explicit
    // !Array.isArray() guard must keep that outcome identical.
    const arrayBody = [{ role: "user", content: "hi" }] as unknown as Record<string, unknown>;
    const out = executor.transformRequest("oc/kimi-k2.6", arrayBody, true, CREDENTIALS);
    assert.ok(Array.isArray(out), "array body must pass through as an array");
    assert.equal((out as unknown[]).length, 1);
  });
});

