import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const require = createRequire(import.meta.url);

/**
 * The bug this guards against only appears in a BROWSER: vitest runs under
 * Node, where `Buffer` is always a global, so every instruction-encoding path
 * passes here and fails only in a real browser — which is how
 * `ReferenceError: Buffer is not defined` reached an admin mid-mint despite a
 * green suite.
 *
 * Deleting `globalThis.Buffer` to reproduce it directly is NOT an option:
 * vitest's own worker RPC needs Buffer, so removing it takes down the runner
 * rather than failing the test. Instead these assert the two facts that
 * actually make the polyfill work — that the dependency needs it, and that the
 * entry point installs it early enough.
 */
describe("Buffer polyfill", () => {
  it("documents WHY it exists: borsh reads a free global Buffer", () => {
    // borsh@0.7 comes in transitively via @coral-xyz/anchor, and every
    // instruction this console broadcasts is encoded through it.
    const src = readFileSync(require.resolve("borsh/lib/index.js"), "utf8");

    // It calls Buffer...
    expect(src).toMatch(/\bBuffer\.(alloc|from|concat)\(/);
    // ...without ever importing it, so it can only resolve as a global.
    expect(src).not.toMatch(/require\(\s*["']buffer["']\s*\)/);
    expect(src).not.toMatch(/from\s+["']buffer["']/);

    // If a future borsh upgrade starts importing Buffer properly, this test
    // fails — that is the signal that the polyfill can be deleted, not a
    // reason to weaken the assertion.
  });

  it("installs a working Buffer global", async () => {
    await import("./bufferPolyfill");

    expect(globalThis.Buffer).toBeDefined();
    // Functional for the operations borsh actually performs, not merely present.
    expect(globalThis.Buffer.alloc(4).length).toBe(4);
    expect(globalThis.Buffer.from("abc", "utf8").length).toBe(3);
    expect(
      globalThis.Buffer.concat([
        globalThis.Buffer.from([1]),
        globalThis.Buffer.from([2]),
      ]).length,
    ).toBe(2);
  });

  it("is the FIRST import in the entry point", () => {
    // Ordering is the fragile part: ES modules evaluate in import order, so the
    // polyfill only beats borsh to the global if nothing is imported ahead of
    // it. A tidy-up that sorts imports alphabetically would silently reinstate
    // the bug, and no runtime test in Node could catch that.
    // vitest's root is the package directory.
    const entry = resolve(process.cwd(), "src/main.tsx");
    expect(existsSync(entry)).toBe(true);
    const firstImport = readFileSync(entry, "utf8")
      .split("\n")
      .find((line) => line.trimStart().startsWith("import "));

    expect(firstImport).toContain("./lib/bufferPolyfill");
  });
});
