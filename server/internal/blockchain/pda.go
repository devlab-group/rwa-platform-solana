package blockchain

import (
	"crypto/sha256"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/mr-tron/base58"
)

// pdaMarker is Solana's fixed suffix for Program Derived Address
// derivation, appended after the program id — see
// https://docs.rs/solana-program/latest/solana_program/pubkey/struct.Pubkey.html#method.find_program_address.
const pdaMarker = "ProgramDerivedAddress"

// maxSeedLen is the per-seed byte limit find_program_address enforces
// (MAX_SEED_LEN in solana-program).
const maxSeedLen = 32

// maxSeeds is the total-seed-count limit (MAX_SEEDS in solana-program).
const maxSeeds = 16

// FindProgramAddress derives a Program Derived Address from seeds and
// programID (base58), matching Solana's find_program_address exactly: it
// tries bump values from 255 down to 0, computing
// sha256(seed0 || seed1 || ... || [bump] || programID(32 bytes) ||
// "ProgramDerivedAddress") for each — the bump is appended to the seed list
// (hashed BEFORE the program id), which create_program_address's actual
// solana-program source does; it is easy to misremember as coming after the
// program id instead, and that ordering silently produces a completely
// different (and wrong) address with no error — and returns the first
// result that is NOT a valid point on the ed25519 curve — an address
// off-curve deliberately has no known private key, which is what makes it
// "program derived" rather than a real wallet. Cross-checked against
// solders (Pubkey.find_program_address) in pda_test.go, not just internal
// self-consistency.
//
// This is the Go equivalent of the TypeScript SDK's
// PublicKey.findProgramAddressSync — used throughout solana/tests/
// fullflow.ts to derive the SAME PDAs (registry, per-wallet compliance
// record, supply-config, vault-config, redemption-config, strategy,
// extra-account-metas) this package now also needs server-side to build
// instructions. Per the frozen solana-chainevent-mapping contract's
// addressing invariant, this is the ONLY place in this codebase that
// derives a PDA — every ChainEvent/config address elsewhere is taken
// verbatim, never recomputed.
func FindProgramAddress(seeds [][]byte, programID string) (addr string, bump uint8, err error) {
	if len(seeds) > maxSeeds {
		return "", 0, fmt.Errorf("blockchain: too many seeds (%d), max %d", len(seeds), maxSeeds)
	}
	for _, s := range seeds {
		if len(s) > maxSeedLen {
			return "", 0, fmt.Errorf("blockchain: seed %q is %d bytes, max %d", s, len(s), maxSeedLen)
		}
	}
	programBytes, err := base58.Decode(programID)
	if err != nil {
		return "", 0, fmt.Errorf("blockchain: decoding program id %q: %w", programID, err)
	}
	if len(programBytes) != 32 {
		return "", 0, fmt.Errorf("blockchain: program id %q decodes to %d bytes, want 32", programID, len(programBytes))
	}

	for bump := 255; bump >= 0; bump-- {
		h := sha256.New()
		for _, s := range seeds {
			h.Write(s)
		}
		h.Write([]byte{byte(bump)})
		h.Write(programBytes)
		h.Write([]byte(pdaMarker))
		candidate := h.Sum(nil)

		// SetBytes succeeding means candidate IS a valid point on the
		// curve, i.e. NOT a PDA (some wallet could theoretically hold its
		// private key) — keep decrementing bump until we find one that
		// ISN'T a curve point.
		if _, onCurveErr := new(edwards25519.Point).SetBytes(candidate); onCurveErr != nil {
			return base58.Encode(candidate), uint8(bump), nil
		}
	}
	return "", 0, fmt.Errorf("blockchain: no valid PDA found for seeds against program %s (exhausted all 256 bumps — practically impossible)", programID)
}

// MustFindProgramAddress is FindProgramAddress for callers with a static,
// already-validated seed/programID (e.g. package-level PDA constants) where
// a derivation failure would be a programming error, not a runtime
// condition — it panics instead of threading an error through every call
// site. Not used for anything derived from operator-supplied config.
func MustFindProgramAddress(seeds [][]byte, programID string) (addr string, bump uint8) {
	addr, bump, err := FindProgramAddress(seeds, programID)
	if err != nil {
		panic("blockchain: MustFindProgramAddress: " + err.Error())
	}
	return addr, bump
}
