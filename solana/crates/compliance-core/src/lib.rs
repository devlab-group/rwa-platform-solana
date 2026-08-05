//! Allowlist + optional KYC-expiry evaluation.
//!
//! Ported from `contracts/src/ComplianceRegistry.sol`. The on-chain
//! `rwa-compliance` program stores one record per wallet and calls these pure
//! functions; keeping the rules here lets them be host-unit-tested
//! (`cargo test -p compliance-core`) and reused verbatim by the transfer hook.
//!
//! Parity points preserved:
//! - `isAllowed` = status is `Allowed` AND (no expiry OR expiry still in the
//!   future, `validUntil >= now`).
//! - A pinned *system address* (Vault / RedemptionEscrow) may only ever hold
//!   `Allowed` with `validUntil == 0`; any other write must be rejected so a
//!   compromised compliance authority can't self-DoS the deployment.

#![forbid(unsafe_code)]

/// Wallet compliance status. The default/unwritten state is [`Unknown`], which
/// is *not* allowed — matching a zeroed Solidity `ComplianceRecord` whose
/// `status` enum is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ComplianceStatus {
    Unknown = 0,
    Allowed = 1,
    Blocked = 2,
}

impl ComplianceStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Unknown),
            1 => Some(Self::Allowed),
            2 => Some(Self::Blocked),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceError {
    /// Attempted to give a pinned system address a non-`Allowed` status or a
    /// non-zero expiry. Mirrors `SystemAddressCannotBeBlocked`.
    SystemAddressCannotBeBlocked,
    InvalidStatus,
}

/// `record.status == Allowed && (validUntil == 0 || validUntil >= now)`.
///
/// `now` is the cluster unix timestamp (`Clock::unix_timestamp`) on-chain.
pub fn is_allowed(status: ComplianceStatus, valid_until: u64, now: u64) -> bool {
    status == ComplianceStatus::Allowed && (valid_until == 0 || valid_until >= now)
}

/// Validate a proposed `(status, validUntil)` write for an account, enforcing the
/// system-address invariant. `is_system` is whether the target account was pinned
/// via `setSystemAddresses`.
pub fn validate_status_change(
    is_system: bool,
    status: ComplianceStatus,
    valid_until: u64,
) -> Result<(), ComplianceError> {
    if is_system && (status != ComplianceStatus::Allowed || valid_until != 0) {
        return Err(ComplianceError::SystemAddressCannotBeBlocked);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_and_blocked_are_never_allowed() {
        assert!(!is_allowed(ComplianceStatus::Unknown, 0, 100));
        assert!(!is_allowed(ComplianceStatus::Blocked, 0, 100));
        assert!(!is_allowed(ComplianceStatus::Blocked, u64::MAX, 100));
    }

    #[test]
    fn allowed_without_expiry_is_permanent() {
        assert!(is_allowed(ComplianceStatus::Allowed, 0, 0));
        assert!(is_allowed(ComplianceStatus::Allowed, 0, u64::MAX));
    }

    #[test]
    fn expiry_boundary_is_inclusive() {
        // validUntil >= now  =>  allowed exactly at the expiry second.
        assert!(is_allowed(ComplianceStatus::Allowed, 100, 100));
        assert!(is_allowed(ComplianceStatus::Allowed, 100, 99));
        assert!(!is_allowed(ComplianceStatus::Allowed, 100, 101));
    }

    #[test]
    fn system_address_must_stay_permanently_allowed() {
        // Non-system accounts: anything goes.
        assert!(validate_status_change(false, ComplianceStatus::Blocked, 0).is_ok());
        assert!(validate_status_change(false, ComplianceStatus::Allowed, 123).is_ok());

        // System account: only Allowed + no expiry.
        assert!(validate_status_change(true, ComplianceStatus::Allowed, 0).is_ok());
        assert_eq!(
            validate_status_change(true, ComplianceStatus::Blocked, 0),
            Err(ComplianceError::SystemAddressCannotBeBlocked)
        );
        assert_eq!(
            validate_status_change(true, ComplianceStatus::Unknown, 0),
            Err(ComplianceError::SystemAddressCannotBeBlocked)
        );
        // Even Allowed-with-expiry is rejected: it would flip to disallowed later.
        assert_eq!(
            validate_status_change(true, ComplianceStatus::Allowed, 1),
            Err(ComplianceError::SystemAddressCannotBeBlocked)
        );
    }

    #[test]
    fn status_roundtrips_through_u8() {
        for v in 0u8..3 {
            assert_eq!(ComplianceStatus::from_u8(v).unwrap() as u8, v);
        }
        assert_eq!(ComplianceStatus::from_u8(3), None);
    }
}
