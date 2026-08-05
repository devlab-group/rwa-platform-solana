import { describe, expect, it } from "vitest";
import {
  investorActionBlocker,
  type InvestorAction,
  type InvestorChainState,
} from "./status";

// These pin the UI's copy of each program's guards. The value of the predicate
// is that the guards are NOT uniform — a single "can transact" flag would be
// wrong for both `cancel` (no pause guard) and `claim` (no compliance
// re-check) — so each asymmetry gets its own test.
const NOW = 1_800_000_000;

function state(over: Partial<InvestorChainState> = {}): InvestorChainState {
  return { nowSeconds: NOW, ...over };
}

const ALL: InvestorAction[] = [
  "buy",
  "requestRedemption",
  "claim",
  "cancel",
  "transfer",
];

describe("investorActionBlocker — pause", () => {
  it("blocks every action except cancel while paused", () => {
    for (const action of ALL) {
      const blocker = investorActionBlocker(action, state({ paused: true }));
      if (action === "cancel") {
        // cancel_redemption carries NO !paused guard and rides the hook's
        // escrow-only bypass: it is the beneficiary's escape hatch, so a
        // pause must not strand their escrowed tokens.
        expect(blocker, "cancel must survive a pause").toBeNull();
      } else {
        expect(blocker, `${action} must be blocked while paused`).toMatch(
          /paused/i,
        );
      }
    }
  });

  it("blocks nothing when the project is not paused", () => {
    for (const action of ALL) {
      expect(
        investorActionBlocker(action, state({ paused: false })),
      ).toBeNull();
    }
  });

  it("blocks nothing when the pause flag has not loaded yet", () => {
    // `paused: undefined` is "not known", not "paused" — the page must not
    // disable every button while GET /project is still in flight.
    for (const action of ALL) {
      expect(investorActionBlocker(action, state())).toBeNull();
    }
  });
});

describe("investorActionBlocker — own compliance", () => {
  it("blocks a Blocked wallet on every action except claim", () => {
    for (const action of ALL) {
      const blocker = investorActionBlocker(
        action,
        state({ ownStatus: "Blocked" }),
      );
      if (action === "claim") {
        // claim_redemption "never re-checks compliance": the funded quote is
        // already committed to the recorded beneficiary and stays payable.
        expect(blocker, "claim must not re-check compliance").toBeNull();
      } else {
        expect(blocker, `${action} must be blocked`).toMatch(/not currently/i);
      }
    }
  });

  it("blocks an Unknown wallet the same as a Blocked one", () => {
    // load_allowed() requires an Allowed record; Unknown fails it too.
    expect(
      investorActionBlocker("buy", state({ ownStatus: "Unknown" })),
    ).toMatch(/not currently/i);
  });

  it("blocks an Allowed wallet whose validUntil has passed", () => {
    // load_allowed(record, key, now) checks expiry against the same clock.
    expect(
      investorActionBlocker(
        "transfer",
        state({ ownStatus: "Allowed", ownValidUntil: NOW - 1 }),
      ),
    ).toMatch(/expired/i);
  });

  it("allows an Allowed wallet whose validUntil is still in the future", () => {
    expect(
      investorActionBlocker(
        "transfer",
        state({ ownStatus: "Allowed", ownValidUntil: NOW + 1 }),
      ),
    ).toBeNull();
  });

  it("treats validUntil 0 as no expiry, not as expired at the epoch", () => {
    expect(
      investorActionBlocker(
        "buy",
        state({ ownStatus: "Allowed", ownValidUntil: 0 }),
      ),
    ).toBeNull();
  });

  it("does not block when there is no wallet session to read a status from", () => {
    // No live X-Wallet-Session means the page has NO evidence either way.
    // Failing closed here would lock out an Allowed investor who simply
    // hasn't re-verified recently; the chain is the authority.
    for (const action of ALL) {
      expect(investorActionBlocker(action, state())).toBeNull();
    }
  });
});

describe("investorActionBlocker — precedence", () => {
  it("reports the pause when a paused project also has a blocked wallet", () => {
    expect(
      investorActionBlocker(
        "buy",
        state({ paused: true, ownStatus: "Blocked" }),
      ),
    ).toMatch(/paused/i);
  });

  it("still reports compliance for cancel on a paused project", () => {
    // cancel skips the pause guard but NOT the beneficiary-Allowed one, so a
    // blocked beneficiary is told the real reason rather than nothing.
    expect(
      investorActionBlocker(
        "cancel",
        state({ paused: true, ownStatus: "Blocked" }),
      ),
    ).toMatch(/not currently/i);
  });
});
