/**
 * TDD — Token refresh retry-before-deactivation.
 *
 * P0 bug: an unrecoverable refresh error (invalid_grant, refresh_token_reused,
 * etc.) immediately sets isActive: false AND testStatus: "expired". The
 * terminal-status guard at line 548 then blocks the connection from ever
 * reaching the EXPIRED_RETRY_MAX retry loop at line 758 — dead code.
 *
 * Verified production root cause: the EXPIRED_RETRY_MAX and
 * EXPIRED_RETRY_BACKOFF_MIN constants were removed in #7719
 * (9a6a846ae), so even if the gate were opened, the retry loop would
 * throw ReferenceError.
 *
 * Fixes:
 * 1. Restore the constants.
 * 2. Gate at 516/548: allow expired connections with retry budget left.
 * 3. Unrecoverable error path: conditional isActive: false, only after
 *    retry budget exhausted.
 * 4. Store expiredRetry in providerSpecificData matching refreshCircuit pattern.
 */
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const TEST_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "omniroute-token-retry-deactivation-"));
process.env.DATA_DIR = TEST_DATA_DIR;
process.env.NODE_ENV = "test";

const core = await import("../../src/lib/db/core.ts");
const providersDb = await import("../../src/lib/db/providers.ts");
const { PROVIDERS } = await import("../../open-sse/config/constants.ts");
const tokenHealthCheck = await import("../../src/lib/tokenHealthCheck.ts");

async function resetStorage() {
  core.resetDbInstance();

  for (let attempt = 0; attempt < 10; attempt++) {
    try {
      if (fs.existsSync(TEST_DATA_DIR)) {
        fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
      }
      break;
    } catch (error: unknown) {
      if ((error?.code === "EBUSY" || error?.code === "EPERM") && attempt < 9) {
        await new Promise((resolve) => setTimeout(resolve, 50 * (attempt + 1)));
      } else {
        throw error;
      }
    }
  }

  fs.mkdirSync(TEST_DATA_DIR, { recursive: true });
}

async function withPatchedProvider(providerId, config, fn) {
  const hadOwnConfig = Object.prototype.hasOwnProperty.call(PROVIDERS, providerId);
  const previousConfig = hadOwnConfig ? PROVIDERS[providerId] : undefined;
  PROVIDERS[providerId] = config;

  try {
    return await fn();
  } finally {
    if (hadOwnConfig) {
      PROVIDERS[providerId] = previousConfig;
    } else {
      delete PROVIDERS[providerId];
    }
  }
}

function createMockFetchForInvalidGrant(tokenUrl: string, spy?: { count: number }) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    if (spy) spy.count += 1;
    const url = typeof input === "string" ? input : (input as Request).url;
    if (url === tokenUrl) {
      return new Response(JSON.stringify({ error: "invalid_grant" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    }
    return originalFetch(
      input as Parameters<typeof originalFetch>[0],
      init as Parameters<typeof originalFetch>[1]
    );
  }) as typeof fetch;
  return originalFetch;
}

const PROVIDER_ID = "custom-oauth-retry-deactivation";
const TOKEN_URL = "https://token-retry.test.invalid/token";
const PROVIDER_CONFIG = {
  tokenUrl: TOKEN_URL,
  clientId: "retry-test-client-id",
  clientSecret: "retry-test-client-secret",
};

async function createRetryTestConnection(overrides: Record<string, unknown> = {}) {
  const connection = await providersDb.createProviderConnection({
    provider: PROVIDER_ID,
    authType: "oauth",
    name: "Retry Test Account",
    email: "[EMAIL_REDACTED]",
    refreshToken: "rt_retry_test",
    accessToken: "at_retry_test",
    healthCheckInterval: 60,
    isActive: true,
    testStatus: "active",
    ...overrides,
  });
  return connection as { id: string; [key: string]: unknown };
}

test.after(async () => {
  core.resetDbInstance();
  try {
    fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
  } catch {
    // ignore cleanup errors
  }
});

// ── Test ①: First refresh failure does NOT set isActive: false ──────────────
test("first unrecoverable refresh error increments expiredRetryCount without setting isActive: false", async () => {
  await resetStorage();
  const originalFetch = createMockFetchForInvalidGrant(TOKEN_URL);

  try {
    await withPatchedProvider(PROVIDER_ID, PROVIDER_CONFIG, async () => {
      const connection = await createRetryTestConnection();

      await tokenHealthCheck.checkConnection({
        ...connection,
        lastHealthCheckAt: new Date(Date.now() - 61 * 60 * 1000).toISOString(),
      });

      const updated = await providersDb.getProviderConnectionById(connection.id);
      const psd = updated?.providerSpecificData as Record<string, unknown> | undefined;

      assert.equal(updated?.isActive, true, "connection must remain active on first failure");
      assert.equal(updated?.testStatus, "expired", "testStatus must be 'expired'");
      assert.equal(psd?.expiredRetry?.count, 1, "expiredRetry.count must increment to 1");
      assert.equal(updated?.errorCode, "invalid_grant", "errorCode must reflect the OAuth error");
      assert.equal(
        updated?.lastErrorType,
        "unrecoverable_refresh_error",
        "lastErrorType must classify the failure"
      );
      assert.equal(updated?.lastErrorSource, "oauth", "lastErrorSource must be 'oauth'");
      assert.ok(
        typeof updated?.lastError === "string" && updated.lastError.length > 0,
        "lastError must be a non-empty descriptive string"
      );
      assert.ok(psd?.expiredRetry?.at, "expiredRetry.at must be set");
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

// ── Test ②: #8182 boundary — an unrecoverable code is NOT re-probed ────────
// An expired connection whose recorded errorCode is permanent (invalid_grant:
// revoked/expired refresh token) must be left untouched by the sweep. The
// bounded retry budget exists for *transient* expiry; spending it on a dead
// OAuth credential is the probe-every-sweep loop #8182 removed, and it also
// overwrote the row's errorCode with a provider-specific sentinel.
test("checkConnection leaves an expired connection with an unrecoverable errorCode untouched", async () => {
  await resetStorage();
  const spy = { count: 0 };
  const originalFetch = createMockFetchForInvalidGrant(TOKEN_URL, spy);

  try {
    await withPatchedProvider(PROVIDER_ID, PROVIDER_CONFIG, async () => {
      const connection = await createRetryTestConnection({
        testStatus: "expired",
        providerSpecificData: {
          expiredRetry: { count: 1, at: new Date(Date.now() - 10 * 60 * 1000).toISOString() },
        },
        lastError: "invalid_grant",
        lastErrorAt: new Date().toISOString(),
        lastErrorType: "unrecoverable_refresh_error",
        lastErrorSource: "oauth",
        errorCode: "invalid_grant",
      });

      await tokenHealthCheck.checkConnection({
        ...connection,
        lastHealthCheckAt: new Date(Date.now() - 61 * 60 * 1000).toISOString(),
      });

      const updated = await providersDb.getProviderConnectionById(connection.id);
      const psd = updated?.providerSpecificData as Record<string, unknown> | undefined;

      // No re-probe: the terminal-status skip must fire before any network call.
      assert.equal(spy.count, 0, "unrecoverable expired connection must not be re-probed");
      // Row left exactly as found: the retry budget is not spent and the
      // diagnostic that classifies the failure is not overwritten.
      assert.equal(psd?.expiredRetry?.count, 1, "expiredRetry.count must stay at 1");
      assert.equal(updated?.errorCode, "invalid_grant", "errorCode must be preserved");
      assert.equal(updated?.isActive, true, "the sweep must not mutate isActive here");
      assert.equal(updated?.testStatus, "expired", "testStatus must remain 'expired'");
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

// ── Test ③: Terminal state only after max retry count (transient expiry) ────
// The budget is spent on a *transient* expiry (no unrecoverable errorCode), so
// the original regression guard is preserved: the connection is refreshed on
// every eligible sweep and only deactivated once the budget is exhausted. The
// permanent-code case is pinned by test ② above.
test("terminal deactivation (isActive: false) only after reaching EXPIRED_RETRY_MAX", async () => {
  await resetStorage();
  const originalFetch = createMockFetchForInvalidGrant(TOKEN_URL);

  try {
    await withPatchedProvider(PROVIDER_ID, PROVIDER_CONFIG, async () => {
      const connection = await createRetryTestConnection({
        testStatus: "expired",
        providerSpecificData: {
          expiredRetry: { count: 2, at: new Date(Date.now() - 30 * 60 * 1000).toISOString() },
        },
        lastError: "transient upstream failure",
        lastErrorAt: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
      });

      await tokenHealthCheck.checkConnection({
        ...connection,
        lastHealthCheckAt: new Date(Date.now() - 61 * 60 * 1000).toISOString(),
      });

      const updated = await providersDb.getProviderConnectionById(connection.id);
      const psd = updated?.providerSpecificData as Record<string, unknown> | undefined;

      // Terminal: isActive must be false after max retries
      assert.equal(updated?.isActive, false, "connection must be deactivated after max retries");
      assert.equal(updated?.testStatus, "expired", "testStatus must be 'expired'");
      assert.equal(psd?.expiredRetry?.count, 3, "expiredRetry.count must reach 3");
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

// ── Test ④: Budget-exhausted connection is strictly skipped by sweep ───────
test("checkConnection strictly skips deactivated connection with exhausted retry budget", async () => {
  await resetStorage();
  let fetchCalled = false;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    fetchCalled = true;
    return originalFetch(
      input as Parameters<typeof originalFetch>[0],
      init as Parameters<typeof originalFetch>[1]
    );
  }) as typeof fetch;

  try {
    await withPatchedProvider(PROVIDER_ID, PROVIDER_CONFIG, async () => {
      const connection = await createRetryTestConnection({
        isActive: false, // already deactivated
        testStatus: "expired",
        providerSpecificData: {
          expiredRetry: { count: 3, at: new Date(Date.now() - 60 * 60 * 1000).toISOString() },
        },
        lastError: "invalid_grant",
        lastErrorAt: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
        lastErrorType: "unrecoverable_refresh_error",
        lastErrorSource: "oauth",
        errorCode: "invalid_grant",
      });

      await tokenHealthCheck.checkConnection({
        ...connection,
        lastHealthCheckAt: new Date(Date.now() - 61 * 60 * 1000).toISOString(),
      });

      const updated = await providersDb.getProviderConnectionById(connection.id);

      // Must be completely skipped: no network calls, no state changes
      assert.equal(
        fetchCalled,
        false,
        "sweep must not make any fetch calls for exhausted connection"
      );
      assert.equal(updated?.isActive, false, "isActive must remain false");
      assert.equal(updated?.testStatus, "expired", "testStatus must remain 'expired'");
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});
