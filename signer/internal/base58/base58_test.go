package base58

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// knownKeys are well-known Solana account keys; each one is a real value an
// auditor could see on a review screen, so a round-trip failure here would be
// a wrong program id shown to a human.
var knownKeys = []struct {
	name   string
	base58 string
	hex    string
}{
	{
		name:   "system program (32 zero bytes)",
		base58: "11111111111111111111111111111111",
		hex:    "0000000000000000000000000000000000000000000000000000000000000000",
	},
	{
		name:   "Token-2022 program",
		base58: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
		hex:    "06ddf6e1ee758fde18425dbce46ccddab61afc4d83b90d27febdf928d8a18bfc",
	},
	{
		name:   "SPL token program",
		base58: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
		hex:    "06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9",
	},
}

func TestEncodeDecode_KnownSolanaKeys(t *testing.T) {
	for _, k := range knownKeys {
		raw, err := hex.DecodeString(k.hex)
		if err != nil {
			t.Fatalf("%s: decoding hex fixture: %v", k.name, err)
		}
		if got := Encode(raw); got != k.base58 {
			t.Errorf("%s: Encode = %s, want %s", k.name, got, k.base58)
		}
		back, err := DecodePubkey(k.base58)
		if err != nil {
			t.Fatalf("%s: DecodePubkey: %v", k.name, err)
		}
		if !bytes.Equal(back[:], raw) {
			t.Errorf("%s: DecodePubkey = %x, want %s", k.name, back, k.hex)
		}
	}
}

func TestEncodeDecode_RoundTripsEveryByteValue(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i * 8)
	}
	back, err := DecodePubkey(Encode(key[:]))
	if err != nil {
		t.Fatalf("DecodePubkey: %v", err)
	}
	if back != key {
		t.Fatalf("round trip = %x, want %x", back, key)
	}
}

// TestDecode_LeadingZerosArePreserved guards the one encoding rule that is
// easy to get wrong and silently corrupts a key: leading zero bytes are
// carried as leading '1' characters, not as part of the big-integer value.
func TestDecode_LeadingZerosArePreserved(t *testing.T) {
	var key [32]byte
	key[31] = 1
	s := Encode(key[:])
	if want := "1111111111111111111111111111111"; s[:len(want)] != want {
		t.Fatalf("Encode(0x00..01) = %q, want %d leading '1's", s, len(want))
	}
	back, err := DecodePubkey(s)
	if err != nil {
		t.Fatalf("DecodePubkey: %v", err)
	}
	if back != key {
		t.Fatalf("round trip = %x, want %x", back, key)
	}
}

func TestDecode_RejectsInvalidInput(t *testing.T) {
	for _, s := range []string{"", "0OIl", "Token!egQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"} {
		if _, err := Decode(s); err == nil {
			t.Errorf("Decode(%q) succeeded, want an error", s)
		}
	}
}

func TestDecodePubkey_RejectsWrongLength(t *testing.T) {
	// 31 bytes, not 32.
	short := Encode(bytes.Repeat([]byte{0xAB}, 31))
	if _, err := DecodePubkey(short); err == nil {
		t.Fatal("DecodePubkey accepted a 31-byte value, want an error")
	}
}
