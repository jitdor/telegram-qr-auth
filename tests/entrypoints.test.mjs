// Import-graph guarantees for the entry points. A deployment that does not use OIDC (or Durable
// Objects) should not load that code, and that only stays true if something checks it.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SRC = join(ROOT, "src");

/** Every src file reachable from `entry` through relative static imports and re-exports. */
function reachable(entry) {
  const seen = new Set();
  const walk = (file) => {
    if (seen.has(file)) return;
    seen.add(file);
    const source = readFileSync(file, "utf8");
    for (const [, spec] of source.matchAll(/(?:import|export)\b[^;'"]*?from\s*["'](\.[^"']+)["']/g)) {
      walk(resolve(dirname(file), spec));
    }
  };
  walk(resolve(ROOT, entry));
  return [...seen].map((file) => relative(SRC, file));
}

test("the main entry point does not load OIDC or Durable Object code", () => {
  const files = reachable("src/index.js");
  assert.deepEqual(files.filter((f) => f.startsWith("oidc/") || f === "do.js"), []);
});

test("the stores entry point does not load OIDC or Durable Object code", () => {
  const files = reachable("src/stores/index.js");
  assert.deepEqual(files.filter((f) => f.startsWith("oidc/") || f === "do.js"), []);
});

test("the do entry point is where Durable Object storage lives, and it is exported by name", async () => {
  const files = reachable("src/do.js");
  assert.ok(files.includes("stores/d1.js") && files.includes("oidc/d1-store.js"));

  const mod = await import("../src/do.js");
  assert.deepEqual(Object.keys(mod).filter((k) => /^(Do|define)/.test(k)).sort(), ["DoLoginStore", "DoOidcStore", "defineQrAuthStorage"]);

  const main = await import("../src/index.js");
  assert.equal(main.DoLoginStore, undefined, "no longer exported from the main entry point");
  assert.equal(main.defineQrAuthStorage, undefined);

  const oidc = await import("../src/oidc/index.js");
  assert.equal(oidc.DoOidcStore, mod.DoOidcStore, "/oidc re-exports the same class");
});

test("package.json exports a do entry point with types", () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  assert.deepEqual(pkg.exports["./do"], { types: "./types/do.d.ts", default: "./src/do.js" });
});
