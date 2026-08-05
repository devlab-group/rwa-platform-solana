// Installs `Buffer` as a browser global.
//
// WHY THIS IS NEEDED: `borsh@0.7.0` — pulled in transitively by
// `@coral-xyz/anchor`, which every instruction this console broadcasts is
// encoded with — references the bare global `Buffer` with no import of its own
// (see its `baseEncode`/`BinaryWriter.writeBuffer`). Node defines that global;
// browsers do not. So `BorshCoder.instruction.encode(...)` throws
// `ReferenceError: Buffer is not defined` at the moment an admin tries to
// broadcast — mint, role change, pause, price update, treasury withdrawal,
// redemption fund/reject. Anchor's own browser build imports Buffer correctly;
// borsh is the one that does not, so the dependency cannot be fixed by
// swapping Anchor entry points.
//
// WHY UNIT TESTS DID NOT CATCH IT: vitest runs under Node, where `Buffer` is
// always a global, so every encode path passes in tests and fails only in a
// real browser. bufferPolyfill.test.ts closes that gap by deleting the global
// first.
//
// This module must be imported FIRST in the entry point, before anything that
// can reach borsh. ES module evaluation follows import order, so a
// side-effect-only import on the first line runs to completion before the
// later imports' module bodies do.
//
// The CSP forbids inline scripts (`script-src 'self'`), so this cannot be a
// <script> tag in index.html — it has to be part of the bundle.
import { Buffer } from "buffer";

declare global {
  // eslint-disable-next-line no-var
  var Buffer: typeof import("buffer").Buffer;
}

// Assigned only when absent: never clobber a real Node Buffer (tests, SSR) with
// the userland shim, and keep repeat imports idempotent.
if (typeof globalThis.Buffer === "undefined") {
  globalThis.Buffer = Buffer;
}

export {};
