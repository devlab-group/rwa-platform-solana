// The transfer-hook program id is the one program id GET /project's
// `addresses` doesn't carry (see lib/wallet.ts's ChainContext doc comment on
// `hookProgramId`) — every other program/mint address lives on
// Project.addresses, seeded 1:1 from server config (see
// server/internal/project/seed.go). It's only ever needed to build a
// buy/redemption/transfer instruction's remaining accounts, so it's fetched
// lazily here, once.
import { useAsync } from "./useAsync";
import { api } from "../lib/client";

/** undefined while loading/on error — callers already guard every call on ctx.hookProgramId being set. */
export function useHookProgramId(): string | undefined {
  const state = useAsync<string | undefined>(async (signal) => {
    const config = await api.getConfig({ signal });
    return config.programIds?.transferHook;
  }, []);
  return state.status === "success" ? state.data : undefined;
}
