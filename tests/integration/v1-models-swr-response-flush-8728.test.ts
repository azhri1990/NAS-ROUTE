import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const CACHE_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "omniroute-swr-cache-8728-"));
process.env.DATA_DIR = CACHE_DATA_DIR;

const catalogCache = await import("../../src/app/api/v1/models/catalogCache.ts");
const REPO_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const BLOCK_MS = 300;

function listen(server: http.Server, socketPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, resolve);
  });
}

function close(server: http.Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

function fetchFromExternalClient(
  socketPath: string
): Promise<{ body: string; receivedAt: number }> {
  const script = [
    'import http from "node:http";',
    "const chunks = [];",
    "const request = http.request({ socketPath: process.argv[1], path: '/v1/models' }, (response) => {",
    "  response.on('data', (chunk) => chunks.push(chunk));",
    "  response.on('end', () => {",
    "    const body = Buffer.concat(chunks).toString('utf8');",
    "    process.stdout.write(JSON.stringify({ body, receivedAt: Date.now() }));",
    "  });",
    "});",
    "request.on('error', (error) => { throw error; });",
    "request.end();",
  ].join("\n");
  const child = spawn(process.execPath, ["--input-type=module", "-e", script, socketPath], {
    stdio: ["ignore", "pipe", "pipe"],
  });

  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (code !== 0) {
        reject(new Error(`external fetch exited ${code}: ${stderr}`));
        return;
      }
      resolve(JSON.parse(stdout));
    });
  });
}

function productionShapedSynchronousRefresh() {
  const models = Array.from({ length: 4_000 }, (_, index) => ({
    id: `provider/model-${index}`,
    object: "model",
    owned_by: "provider",
    display_name: `Model ${index}`,
  }));
  const startedAt = Date.now();
  do {
    JSON.stringify({ object: "list", data: models });
  } while (Date.now() - startedAt < BLOCK_MS);
}

test.after(() => {
  fs.rmSync(CACHE_DATA_DIR, { recursive: true, force: true });
});

/**
 * Contract note: #8728 originally shipped an injectable `CatalogCachePolicy` (a
 * per-call SWR window accessor + a Next `after()` refresh scheduler) and an
 * unbounded `CATALOG_STALE_WHILE_REVALIDATE_MS`. #9199 deliberately replaced
 * both: the window is a fixed 30 s constant and the refresh is deferred
 * internally by `setTimeout(…, 0)`, so no caller supplies a policy and nothing
 * outside a Next request scope can invoke `after()`. An unbounded window let a
 * refresh that kept failing pin an ancient catalog forever.
 *
 * These assertions used to pin the removed API and the `after()` wiring, which
 * #9199 deleted — they were the reason this file stayed red. They now guard the
 * shipped contract *and* the failure mode that produced the red: a caller
 * passing a scheduler that `resolveCachedCatalogResponse` silently ignores,
 * which looks wired but schedules nothing.
 */
test("the /v1/models catalog defers its background refresh itself, with no dead scheduler arg", () => {
  const routeSource = fs.readFileSync(
    path.join(REPO_ROOT, "src/app/api/v1/models/route.ts"),
    "utf8"
  );
  const cacheSource = fs.readFileSync(
    path.join(REPO_ROOT, "src/app/api/v1/models/catalogCache.ts"),
    "utf8"
  );

  // getUnifiedModelsResponse(request, corsHeaders) takes exactly two arguments;
  // a third "policy" object was silently dropped at runtime.
  assert.match(routeSource, /getUnifiedModelsResponse\(\s*request,\s*\{\s*\}\s*\)/);
  assert.doesNotMatch(routeSource, /scheduleBackgroundRefresh/);
  assert.doesNotMatch(routeSource, /next\/server/);

  // The deferral that keeps the stale body ahead of the blocking rebuild lives in
  // the cache module, against a bounded window.
  assert.match(cacheSource, /now - cached\.expiresAt <= CATALOG_STALE_WHILE_REVALIDATE_MS/);
  assert.match(cacheSource, /function scheduleBackgroundRefresh\([\s\S]*?setTimeout\(/);
  assert.match(cacheSource, /CATALOG_STALE_WHILE_REVALIDATE_MS = 30_000/);
});

test("an external client receives the stale body before synchronous refresh finishes blocking", async (t) => {
  catalogCache.__resetCatalogBuilderRunsForTest();
  const socketDir = fs.mkdtempSync(path.join(os.tmpdir(), "omniroute-swr-http-8728-"));
  const socketPath = path.join(socketDir, "catalog.sock");

  let buildCount = 0;
  let responseFinishedAt = 0;
  let refreshStartedAt = 0;
  let refreshFinishedAt = 0;

  const server = http.createServer(async (incoming, outgoing) => {
    const url = `http://127.0.0.1${incoming.url || "/"}`;
    // Recorded on every response so the refresh ordering can be checked without
    // injecting a scheduler the module no longer accepts.
    outgoing.once("finish", () => {
      responseFinishedAt = Date.now();
    });
    const response = await catalogCache.resolveCachedCatalogResponse(
      new Request(url),
      { corsHeaders: {}, diagnosticHeaders: {} },
      async () => {
        buildCount++;
        if (buildCount > 1) {
          refreshStartedAt = Date.now();
          productionShapedSynchronousRefresh();
          refreshFinishedAt = Date.now();
        }
        return {
          body: buildCount > 1 ? "new" : "old",
          headers: { "content-type": "text/plain" },
          status: 200,
          cacheTTL: 60_000,
        };
      }
    );

    outgoing.writeHead(response.status, Object.fromEntries(response.headers.entries()));
    outgoing.end(await response.text());
  });

  try {
    await listen(server, socketPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EPERM") {
      t.skip("sandbox does not permit opening HTTP listener sockets");
      fs.rmSync(socketDir, { recursive: true, force: true });
      return;
    }
    throw error;
  }
  try {
    assert.equal((await fetchFromExternalClient(socketPath)).body, "old");
    catalogCache.__expireCatalogCacheForTest();

    const stale = await fetchFromExternalClient(socketPath);
    await catalogCache.__flushCatalogBackgroundRefreshForTest();

    assert.equal(stale.body, "old");
    assert.equal(buildCount, 2, "the stale request must trigger exactly one background rebuild");
    assert.ok(refreshStartedAt >= responseFinishedAt, "refresh must start after response finish");
    assert.ok(
      stale.receivedAt < refreshFinishedAt,
      `external client received stale body at ${stale.receivedAt}, after refresh finished at ${refreshFinishedAt}`
    );
    assert.ok(
      refreshFinishedAt - refreshStartedAt >= BLOCK_MS,
      "refresh did not exercise the synchronous blocking window"
    );
  } finally {
    await close(server);
    fs.rmSync(socketDir, { recursive: true, force: true });
    catalogCache.__resetCatalogBuilderRunsForTest();
  }
});
