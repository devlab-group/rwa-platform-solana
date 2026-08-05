// @vitest-environment node
//
// Coverage for assertClusterGenesis (optional hardening): the
// once-per-session-per-endpoint cluster-identity cross-check against a
// pinned VITE_SOLANA_CLUSTER_GENESIS. Uses a minimal fake Connection (just
// the `rpcEndpoint` + `getGenesisHash` surface this function touches) rather
// than a real @solana/web3.js Connection, same spirit as
// wallet.instructions.test.ts's connectionStub.
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Connection } from "@solana/web3.js";
import { assertClusterGenesis } from "./provider";
import { PinMismatchError } from "./pins";

function fakeConnection(
  rpcEndpoint: string,
  getGenesisHash: () => Promise<string>,
): Connection {
  return { rpcEndpoint, getGenesisHash } as unknown as Connection;
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("assertClusterGenesis", () => {
  it("is a no-op (never calls getGenesisHash) when unpinned", async () => {
    const getGenesisHash = vi.fn().mockResolvedValue("whatever");
    const connection = fakeConnection("https://a.example.com", getGenesisHash);

    await expect(assertClusterGenesis(connection)).resolves.toBeUndefined();
    expect(getGenesisHash).not.toHaveBeenCalled();
  });

  it("resolves without throwing when the genesis hash matches the pin", async () => {
    vi.stubEnv("VITE_SOLANA_CLUSTER_GENESIS", "genesis-abc");
    const getGenesisHash = vi.fn().mockResolvedValue("genesis-abc");
    const connection = fakeConnection("https://b.example.com", getGenesisHash);

    await expect(assertClusterGenesis(connection)).resolves.toBeUndefined();
    expect(getGenesisHash).toHaveBeenCalledTimes(1);
  });

  it("throws PinMismatchError when the genesis hash disagrees with the pin", async () => {
    vi.stubEnv("VITE_SOLANA_CLUSTER_GENESIS", "genesis-abc");
    const getGenesisHash = vi.fn().mockResolvedValue("genesis-devnet");
    const connection = fakeConnection("https://c.example.com", getGenesisHash);

    await expect(assertClusterGenesis(connection)).rejects.toThrow(
      PinMismatchError,
    );
  });

  it("checks a given RPC endpoint only once per session (cached)", async () => {
    vi.stubEnv("VITE_SOLANA_CLUSTER_GENESIS", "genesis-abc");
    const getGenesisHash = vi.fn().mockResolvedValue("genesis-abc");
    const connection = fakeConnection("https://d.example.com", getGenesisHash);

    await assertClusterGenesis(connection);
    await assertClusterGenesis(connection);
    await assertClusterGenesis(connection);

    expect(getGenesisHash).toHaveBeenCalledTimes(1);
  });

  it("does not permanently cache a failed check — a later call retries", async () => {
    vi.stubEnv("VITE_SOLANA_CLUSTER_GENESIS", "genesis-abc");
    const getGenesisHash = vi
      .fn()
      .mockRejectedValueOnce(new Error("rpc timeout"))
      .mockResolvedValueOnce("genesis-abc");
    const connection = fakeConnection("https://e.example.com", getGenesisHash);

    await expect(assertClusterGenesis(connection)).rejects.toThrow("rpc timeout");
    // Give the cache-eviction .catch() a microtask turn to run before retrying.
    await Promise.resolve();
    await expect(assertClusterGenesis(connection)).resolves.toBeUndefined();
    expect(getGenesisHash).toHaveBeenCalledTimes(2);
  });
});
