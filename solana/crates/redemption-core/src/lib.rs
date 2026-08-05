//! Redemption state-machine guards.
//!
//! Ported from `contracts/src/RedemptionEscrow.sol` and
//! `docs/spec/redemption-state-machine.md`:
//!
//! ```text
//! None -> Pending -> { Funded -> Completed | Rejected | Cancelled }
//! ```
//!
//! The on-chain `rwa-redemption` program owns the accounts and token transfers;
//! this crate holds the *pure* transition rules so they can be host-unit-tested
//! (`cargo test -p redemption-core`). The asset legs (pull/return RWA, pull/pay
//! quote) and the compliance re-checks live in the program, at the points the
//! spec's Guard column requires.

#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RedemptionStatus {
    /// Slot never written — a request id that does not exist.
    None = 0,
    Pending = 1,
    Funded = 2,
    Completed = 3,
    Rejected = 4,
    Cancelled = 5,
}

impl RedemptionStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::Pending),
            2 => Some(Self::Funded),
            3 => Some(Self::Completed),
            4 => Some(Self::Rejected),
            5 => Some(Self::Cancelled),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedemptionError {
    /// Transition requires `Pending` (fund / reject / cancel). `NotPending`.
    NotPending,
    /// Claim requires `Funded`. `NotFunded`.
    NotFunded,
    /// `cancelRedemption` caller is not the recorded beneficiary.
    NotBeneficiary,
    /// `now < createdAt + timeout`. `TimeoutNotReached`.
    TimeoutNotReached,
}

/// `fundRedemption` / `rejectRedemption` precondition: must be `Pending`.
pub fn ensure_pending(status: RedemptionStatus) -> Result<(), RedemptionError> {
    if status == RedemptionStatus::Pending {
        Ok(())
    } else {
        Err(RedemptionError::NotPending)
    }
}

/// `claimRedemption` precondition: must be `Funded`.
pub fn ensure_funded(status: RedemptionStatus) -> Result<(), RedemptionError> {
    if status == RedemptionStatus::Funded {
        Ok(())
    } else {
        Err(RedemptionError::NotFunded)
    }
}

/// `cancelRedemption` guard: `Pending`, caller is the beneficiary, and the
/// timeout has elapsed. `created_at + timeout` is computed with saturating add
/// so a pathological config can never wrap the deadline earlier.
pub fn can_cancel(
    status: RedemptionStatus,
    caller_is_beneficiary: bool,
    created_at: u64,
    timeout: u64,
    now: u64,
) -> Result<(), RedemptionError> {
    ensure_pending(status)?;
    if !caller_is_beneficiary {
        return Err(RedemptionError::NotBeneficiary);
    }
    let available_at = created_at.saturating_add(timeout);
    if now < available_at {
        return Err(RedemptionError::TimeoutNotReached);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use RedemptionStatus::*;

    #[test]
    fn fund_and_reject_require_pending() {
        assert!(ensure_pending(Pending).is_ok());
        for s in [None, Funded, Completed, Rejected, Cancelled] {
            assert_eq!(ensure_pending(s), Err(RedemptionError::NotPending));
        }
    }

    #[test]
    fn claim_requires_funded() {
        assert!(ensure_funded(Funded).is_ok());
        for s in [None, Pending, Completed, Rejected, Cancelled] {
            assert_eq!(ensure_funded(s), Err(RedemptionError::NotFunded));
        }
    }

    #[test]
    fn funded_cannot_be_rejected_or_cancelled() {
        // Mirrors test_rejectRedemption_afterFundReverts / _cancel_afterFundReverts.
        assert_eq!(ensure_pending(Funded), Err(RedemptionError::NotPending));
        assert_eq!(
            can_cancel(Funded, true, 0, 10, 1_000_000),
            Err(RedemptionError::NotPending)
        );
    }

    #[test]
    fn cancel_requires_beneficiary() {
        assert_eq!(
            can_cancel(Pending, false, 100, 50, 1_000),
            Err(RedemptionError::NotBeneficiary)
        );
    }

    #[test]
    fn cancel_timeout_boundary() {
        // available_at = 100 + 50 = 150. now must be >= 150.
        assert_eq!(
            can_cancel(Pending, true, 100, 50, 149),
            Err(RedemptionError::TimeoutNotReached)
        );
        assert!(can_cancel(Pending, true, 100, 50, 150).is_ok());
        assert!(can_cancel(Pending, true, 100, 50, 151).is_ok());
    }

    #[test]
    fn cancel_timeout_add_saturates() {
        // Would-overflow deadline stays at u64::MAX (never becomes reachable early).
        assert_eq!(
            can_cancel(Pending, true, u64::MAX, u64::MAX, u64::MAX - 1),
            Err(RedemptionError::TimeoutNotReached)
        );
    }

    #[test]
    fn status_roundtrips_through_u8() {
        for v in 0u8..6 {
            assert_eq!(RedemptionStatus::from_u8(v).unwrap() as u8, v);
        }
        assert_eq!(RedemptionStatus::from_u8(6), Option::None);
    }
}
