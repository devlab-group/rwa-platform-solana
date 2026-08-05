package blockchain

import (
	"testing"

	"github.com/mr-tron/base58"
)

// pdaVector is one (seeds, programID) -> (address, bump) case, cross-checked
// against solders (Pubkey.find_program_address — a widely-used, independent
// Rust-backed Python Solana SDK), NOT just this package's own internal
// consistency. Generating these caught a real bug during development: the
// bump seed byte must be hashed BEFORE the program id (appended to the seed
// list), not after — see FindProgramAddress's doc comment.
var pdaVectors = []struct {
	name      string
	seeds     [][]byte
	programID string
	wantAddr  string
	wantBump  uint8
}{
	{
		name:      "registry seed against supply-controller-shaped program id",
		seeds:     [][]byte{[]byte("registry")},
		programID: "SuppLyCtR1111111111111111111111111111111111",
		wantAddr:  "GvopmZw6MC3AxUXwqNw3qHZBoazyKM3tBmtpBp8JaF3m",
		wantBump:  255,
	},
	{
		name:      "record seed for wallet 1",
		seeds:     [][]byte{[]byte("record"), mustB58(nil, "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi")},
		programID: "SuppLyCtR1111111111111111111111111111111111",
		wantAddr:  "E5ba8VGJwm8U8Jx3wUJWPfijDbQvYgxjTAuiQTFvbNNu",
		wantBump:  254,
	},
	{
		name:      "record seed for wallet 2 (different bump than wallet 1)",
		seeds:     [][]byte{[]byte("record"), mustB58(nil, "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR")},
		programID: "SuppLyCtR1111111111111111111111111111111111",
		wantAddr:  "GBA8ztE2UMMYsJcY2tj6cTcvFmJLHKjYku1YCjYd6EMC",
		wantBump:  253,
	},
	{
		name:      "strategy seed against a different program id",
		seeds:     [][]byte{[]byte("strategy")},
		programID: "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",
		wantAddr:  "87owmiPmtoMabLYZAqP5fjM4KJxeegbhuEFzmC2DTbwY",
		wantBump:  255,
	},
	{
		name:      "supply-config seed",
		seeds:     [][]byte{[]byte("supply-config")},
		programID: "QWmroo4YnnMqYW3cnxWkFdaTxGD3P7vMSzwMHGbUzwF",
		wantAddr:  "9ULo7MzVNwHCmv4FQLrVbJo7Ey4adRMPtpWF8HkPLBnX",
		wantBump:  255,
	},
}

func mustB58(t *testing.T, s string) []byte {
	b, err := base58.Decode(s)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	return b
}

func TestFindProgramAddressMatchesSoldersReferenceVectors(t *testing.T) {
	for _, v := range pdaVectors {
		t.Run(v.name, func(t *testing.T) {
			addr, bump, err := FindProgramAddress(v.seeds, v.programID)
			if err != nil {
				t.Fatalf("FindProgramAddress: %v", err)
			}
			if addr != v.wantAddr || bump != v.wantBump {
				t.Errorf("got (%s, %d), want (%s, %d)", addr, bump, v.wantAddr, v.wantBump)
			}
		})
	}
}

// TestFindProgramAddressIsDeterministic covers the property callers
// actually rely on: deriving the same (seeds, programID) pair twice must
// always produce the identical address+bump, since the record PDA is
// re-derived on every set_status call rather than cached.
func TestFindProgramAddressIsDeterministic(t *testing.T) {
	addr1, bump1, err := FindProgramAddress([][]byte{[]byte("record"), mustB58(t, "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi")}, "SuppLyCtR1111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	addr2, bump2, err := FindProgramAddress([][]byte{[]byte("record"), mustB58(t, "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi")}, "SuppLyCtR1111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	if addr1 != addr2 || bump1 != bump2 {
		t.Errorf("non-deterministic: (%s,%d) vs (%s,%d)", addr1, bump1, addr2, bump2)
	}
}

// TestFindProgramAddressDifferentSeedsDifferentAddress is a basic sanity
// check that seeds actually participate in the hash (not just the program
// id) — two different wallets must not collide on the same record PDA.
func TestFindProgramAddressDifferentSeedsDifferentAddress(t *testing.T) {
	addr1, _, err := FindProgramAddress([][]byte{[]byte("record"), mustB58(t, "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi")}, "SuppLyCtR1111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	addr2, _, err := FindProgramAddress([][]byte{[]byte("record"), mustB58(t, "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR")}, "SuppLyCtR1111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	if addr1 == addr2 {
		t.Error("two different wallets derived the same record PDA")
	}
}

func TestFindProgramAddressRejectsMalformedProgramID(t *testing.T) {
	if _, _, err := FindProgramAddress([][]byte{[]byte("registry")}, "not-valid-base58-0OIl"); err == nil {
		t.Fatal("expected an error for a malformed program id")
	}
}

func TestFindProgramAddressRejectsOversizedSeed(t *testing.T) {
	oversized := make([]byte, maxSeedLen+1)
	if _, _, err := FindProgramAddress([][]byte{oversized}, "SuppLyCtR1111111111111111111111111111111111"); err == nil {
		t.Fatal("expected an error for a seed exceeding the 32-byte limit")
	}
}

func TestFindProgramAddressRejectsTooManySeeds(t *testing.T) {
	seeds := make([][]byte, maxSeeds+1)
	for i := range seeds {
		seeds[i] = []byte("x")
	}
	if _, _, err := FindProgramAddress(seeds, "SuppLyCtR1111111111111111111111111111111111"); err == nil {
		t.Fatal("expected an error for more than 16 seeds")
	}
}

func TestMustFindProgramAddressPanicsOnError(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected MustFindProgramAddress to panic on an invalid program id")
		}
	}()
	MustFindProgramAddress([][]byte{[]byte("registry")}, "not-valid-base58-0OIl")
}
