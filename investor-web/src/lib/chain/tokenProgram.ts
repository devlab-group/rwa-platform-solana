// Resolves which SPL token program actually owns a given mint. The client
// used to always assume the quote leg was legacy SPL
// Token, but the on-chain programs pin `quote_token_program = *quote_mint.owner`
// (see `validate_quote_mint`) and accept legacy SPL OR Token-2022 — a
// Token-2022 quote mint made every buy/claim fail. Reading the mint
// account's own owner mirrors that on-chain check exactly instead of
// guessing.
import { Connection, PublicKey } from "@solana/web3.js";
import { TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID } from "@solana/spl-token";

// A mint's owning program never changes post-creation, so this is safe to
// cache for the life of the tab — avoids a redundant getAccountInfo per call
// within one session.
const cache = new Map<string, PublicKey>();

export async function resolveTokenProgram(
  connection: Connection,
  mint: PublicKey,
): Promise<PublicKey> {
  const key = mint.toBase58();
  const cached = cache.get(key);
  if (cached) return cached;

  const info = await connection.getAccountInfo(mint);
  if (!info) {
    throw new Error(`Mint account not found: ${mint.toBase58()}`);
  }
  const owner = info.owner;
  if (!owner.equals(TOKEN_PROGRAM_ID) && !owner.equals(TOKEN_2022_PROGRAM_ID)) {
    throw new Error(
      `Unsupported token program for mint ${mint.toBase58()}: ${owner.toBase58()}`,
    );
  }
  cache.set(key, owner);
  return owner;
}
