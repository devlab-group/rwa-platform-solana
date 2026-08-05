//! Fixed-price purchase/redemption quoting.
//!
//! Ported 1:1 from `contracts/src/pricing/FixedPriceStrategy.sol`:
//!
//! ```text
//! quote = mulDiv(tokenAmount, pricePerWholeToken, 10**tokenDecimals)
//! quotePurchase   rounds UP   (Ceil)
//! quoteRedemption rounds DOWN (Floor)
//! ```
//!
//! `price` is quote-token smallest-units per one whole RWA token (10**decimals
//! base units), matching `shared/vectors/arithmetic.json`. All amounts are `u64`
//! because SPL / Token-2022 balances are `u64`; the intermediate product is done
//! in `u128` and the result must fit back into `u64` or [`PricingError::Overflow`]
//! is returned (the on-chain caller turns that into a revert, exactly as the
//! Solidity `mulDiv` reverts on overflow).
//!
//! This crate has no Solana dependency so it is unit-tested on the host with
//! `cargo test -p pricing-math`, including the frozen `arithmetic.json` vectors.

#![forbid(unsafe_code)]

/// Largest `tokenDecimals` accepted, mirroring `RWAFactory.MAX_DECIMALS`. `10**36`
/// still fits in `u128`; `10**39` would not.
pub const MAX_DECIMALS: u8 = 36;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PricingError {
    /// Price must be non-zero, matching `FixedPriceStrategy`'s `ZeroPrice`.
    ZeroPrice,
    /// `tokenDecimals` exceeds [`MAX_DECIMALS`].
    DecimalsTooLarge,
    /// The `u128` product overflowed, or the quote did not fit back into `u64`.
    Overflow,
}

/// `10**decimals` as `u128`, or [`PricingError::DecimalsTooLarge`].
///
/// NOTE: this crate deliberately restricts itself to plain `*`, `/`, comparisons
/// and `as` casts on `u128`. The `checked_pow` / `checked_mul` / `TryFrom<u128>`
/// helpers lower to compiler-rt intrinsics (`__muloti4`, overflow-checked pow,
/// `__udivti3` wrappers) that fault under the pinned Agave SBF platform-tools,
/// whereas the primitive operators are emitted inline and execute correctly.
/// All inputs here are bounded (`token_amount`/`price` are `u64`, `decimals ≤ 36`)
/// so `u64 * u64 < 2^128` and `10^36 < 2^128` never overflow `u128`.
pub fn pow10(decimals: u8) -> Result<u128, PricingError> {
    if decimals > MAX_DECIMALS {
        return Err(PricingError::DecimalsTooLarge);
    }
    let mut p: u128 = 1;
    let mut i = 0u8;
    while i < decimals {
        p *= 10;
        i += 1;
    }
    Ok(p)
}

/// `a * b` for `a, b` derived from `u64`s — the product always fits `u128`
/// (`(2^64-1)^2 < 2^128`), so the plain multiply never overflows.
#[inline]
fn mul_u128(a: u128, b: u128) -> u128 {
    a * b
}

fn mul_div_floor(a: u128, b: u128, denom: u128) -> Result<u128, PricingError> {
    Ok(mul_u128(a, b) / denom)
}

fn mul_div_ceil(a: u128, b: u128, denom: u128) -> Result<u128, PricingError> {
    let product = mul_u128(a, b);
    if product == 0 {
        return Ok(0);
    }
    // (product + denom - 1) / denom, without overflowing on the `+ denom`.
    Ok((product - 1) / denom + 1)
}

fn to_u64(value: u128) -> Result<u64, PricingError> {
    if value > u64::MAX as u128 {
        return Err(PricingError::Overflow);
    }
    Ok(value as u64)
}

/// Quote paid by a buyer for `token_amount` base units — rounds **up**.
///
/// Mirrors `FixedPriceStrategy.quotePurchase` (`Math.Rounding.Ceil`).
pub fn quote_purchase(
    token_amount: u64,
    price_per_whole_token: u64,
    token_decimals: u8,
) -> Result<u64, PricingError> {
    if price_per_whole_token == 0 {
        return Err(PricingError::ZeroPrice);
    }
    let denom = pow10(token_decimals)?;
    to_u64(mul_div_ceil(
        token_amount as u128,
        price_per_whole_token as u128,
        denom,
    )?)
}

/// Quote paid out to a redeemer for `token_amount` base units — rounds **down**.
///
/// Mirrors `FixedPriceStrategy.quoteRedemption` (`Math.Rounding.Floor`).
pub fn quote_redemption(
    token_amount: u64,
    price_per_whole_token: u64,
    token_decimals: u8,
) -> Result<u64, PricingError> {
    if price_per_whole_token == 0 {
        return Err(PricingError::ZeroPrice);
    }
    let denom = pow10(token_decimals)?;
    to_u64(mul_div_floor(
        token_amount as u128,
        price_per_whole_token as u128,
        denom,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[test]
    fn zero_price_rejected() {
        assert_eq!(quote_purchase(1, 0, 6), Err(PricingError::ZeroPrice));
        assert_eq!(quote_redemption(1, 0, 6), Err(PricingError::ZeroPrice));
    }

    #[test]
    fn zero_amount_is_zero_quote() {
        assert_eq!(quote_purchase(0, 2_000_000, 18), Ok(0));
        assert_eq!(quote_redemption(0, 2_000_000, 18), Ok(0));
    }

    #[test]
    fn ceil_vs_floor_on_fractional() {
        // 0.5 whole token at price 1 (1 unit per whole) => 0.5 units.
        // purchase rounds up to 1, redemption floors to 0.
        let half = 5u64 * 10u64.pow(17); // 0.5 * 10**18
        assert_eq!(quote_purchase(half, 1, 18), Ok(1));
        assert_eq!(quote_redemption(half, 1, 18), Ok(0));
    }

    #[test]
    fn decimals_bounds() {
        assert_eq!(pow10(0), Ok(1));
        assert_eq!(pow10(36).map(|_| ()), Ok(()));
        assert_eq!(pow10(37), Err(PricingError::DecimalsTooLarge));
    }

    #[test]
    fn overflow_is_reported_not_wrapped() {
        // u64::MAX * u64::MAX overflows u128? No — it fits (< 2^128). But with a
        // tiny denominator the product itself is the ceiling case; force a real
        // u128 overflow via decimals path is impossible, so check the u64 clamp:
        // huge amount * huge price / 1 overflows u64 on the way back down.
        assert_eq!(
            quote_purchase(u64::MAX, u64::MAX, 0),
            Err(PricingError::Overflow)
        );
    }

    // ---- Frozen cross-language parity: shared/vectors/arithmetic.json ----

    #[derive(Deserialize)]
    struct Case {
        name: String,
        #[serde(rename = "tokenDecimals")]
        token_decimals: u8,
        #[serde(rename = "purchasePricePerWholeToken")]
        purchase_price: String,
        #[serde(rename = "redemptionPricePerWholeToken")]
        redemption_price: String,
        #[serde(rename = "tokenAmount")]
        token_amount: String,
        #[serde(rename = "expectedPurchaseQuote")]
        expected_purchase: String,
        #[serde(rename = "expectedRedemptionQuote")]
        expected_redemption: String,
    }

    #[derive(Deserialize)]
    struct Vectors {
        cases: Vec<Case>,
    }

    #[test]
    fn matches_shared_arithmetic_vectors() {
        // Path is relative to this crate's manifest dir at test time.
        let raw = include_str!("../../../../shared/vectors/arithmetic.json");
        let vectors: Vectors = serde_json::from_str(raw).expect("parse arithmetic.json");
        for c in &vectors.cases {
            let amount: u64 = c.token_amount.parse().unwrap();
            let p_price: u64 = c.purchase_price.parse().unwrap();
            let r_price: u64 = c.redemption_price.parse().unwrap();
            let exp_p: u64 = c.expected_purchase.parse().unwrap();
            let exp_r: u64 = c.expected_redemption.parse().unwrap();
            assert_eq!(
                quote_purchase(amount, p_price, c.token_decimals),
                Ok(exp_p),
                "purchase mismatch for case {}",
                c.name
            );
            assert_eq!(
                quote_redemption(amount, r_price, c.token_decimals),
                Ok(exp_r),
                "redemption mismatch for case {}",
                c.name
            );
        }
    }
}
