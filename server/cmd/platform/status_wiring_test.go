package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-tron/base58"
)

// TestLoadComplianceKeyFromBase58 covers the inline-secret-key form —
// tried first (see loadComplianceKey's doc comment).
func TestLoadComplianceKeyFromBase58(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := loadComplianceKey(base58.Encode(priv))
	if err != nil {
		t.Fatalf("loadComplianceKey: %v", err)
	}
	if !got.Equal(priv) {
		t.Error("loaded key does not match the original")
	}
}

// TestLoadComplianceKeyFromKeypairFile covers the Solana CLI keypair
// JSON file fallback (a JSON array of 64 integers, `solana-keygen new`'s
// output shape).
func TestLoadComplianceKeyFromKeypairFile(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ints := make([]int, len(priv))
	for i, b := range priv {
		ints[i] = int(b)
	}
	raw, err := json.Marshal(ints)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "keypair.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := loadComplianceKey(path)
	if err != nil {
		t.Fatalf("loadComplianceKey: %v", err)
	}
	if !got.Equal(priv) {
		t.Error("loaded key does not match the original")
	}
}

func TestLoadComplianceKeyRejectsGarbage(t *testing.T) {
	if _, err := loadComplianceKey("neither-base58-nor-a-real-file-path"); err == nil {
		t.Fatal("expected an error for a value that is neither a valid secret key nor a readable file")
	}
}

func TestLoadComplianceKeyRejectsMalformedKeypairFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`[1,2,3]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadComplianceKey(path); err == nil {
		t.Fatal("expected an error for a keypair file with the wrong number of bytes")
	}
}

func TestLoadComplianceKeyRejectsOutOfRangeByte(t *testing.T) {
	ints := make([]int, ed25519.PrivateKeySize)
	ints[0] = 999 // out of byte range
	raw, err := json.Marshal(ints)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadComplianceKey(path); err == nil {
		t.Fatal("expected an error for an out-of-range byte value")
	}
}

// TestLoadComplianceKeyErrorsNeverEchoTheRawValue is a regression
// guard: a near-miss malformed inline secret (e.g. a mistyped
// base58 key an operator meant to paste inline) must never be echoed
// verbatim in the returned error — buildApp logs it via log.Printf,
// so leaking it there would write live key material into the server log.
// This covers both the "neither form works" case (the old code wrapped
// os.ReadFile's *fs.PathError, which embeds its path argument — here, the
// raw value itself) and the keypair-file-path echoed in the two
// keypair-parsing error messages.
func TestLoadComplianceKeyErrorsNeverEchoTheRawValue(t *testing.T) {
	const secret = "this-looks-like-a-near-miss-secret-1234567890"
	if _, err := loadComplianceKey(secret); err == nil {
		t.Fatal("expected an error for a value that is neither valid base58 nor a readable file")
	} else if strings.Contains(err.Error(), secret) {
		t.Errorf("error echoes the raw config value verbatim: %v", err)
	}

	// A path that itself looks like sensitive material (as an operator's
	// real mistyped secret would) must not appear in a keypair-parsing
	// error either.
	sensitivePath := filepath.Join(t.TempDir(), "definitely-not-my-real-secret-key-material")
	if err := os.WriteFile(sensitivePath, []byte(`[1,2,3]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadComplianceKey(sensitivePath); err == nil {
		t.Fatal("expected an error for a malformed keypair file")
	} else if strings.Contains(err.Error(), sensitivePath) {
		t.Errorf("error echoes the config-supplied path verbatim: %v", err)
	}
}
