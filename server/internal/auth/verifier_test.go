package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/mr-tron/base58"
)

func TestNewVerifierReturnsVerifier(t *testing.T) {
	if _, ok := NewVerifier().(verifier); !ok {
		t.Errorf("NewVerifier() = %T, want verifier", NewVerifier())
	}
}

func TestVerifierValidateAddress(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := verifier{}
	if !v.ValidateAddress(base58.Encode(pub)) {
		t.Error("expected a valid 32-byte base58 pubkey to validate")
	}
	if v.ValidateAddress("not-base58-!@#$") {
		t.Error("expected invalid base58 to be rejected")
	}
	if v.ValidateAddress(base58.Encode([]byte{1, 2, 3})) {
		t.Error("expected a too-short decoded payload to be rejected")
	}
}

func TestVerifierVerifyHappyPath(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	address := base58.Encode(pub)
	message := "RWA Platform admin login.\nNonce: abc123"
	sig := ed25519.Sign(priv, []byte(message))

	v := verifier{}
	recovered, err := v.Verify(message, address, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if recovered != address {
		t.Errorf("recovered = %q, want %q", recovered, address)
	}
}

func TestVerifierVerifyRejectsWrongKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := "RWA Platform admin login.\nNonce: abc123"
	sig := ed25519.Sign(priv, []byte(message))

	v := verifier{}
	// The signature was produced by priv, but address claims to be a
	// DIFFERENT (unrelated) public key — verification must fail.
	if _, err := v.Verify(message, base58.Encode(otherPub), sig); err == nil {
		t.Fatal("expected an error verifying against the wrong public key")
	}
}

func TestVerifierVerifyRejectsMalformedSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	address := base58.Encode(pub)
	message := "RWA Platform admin login.\nNonce: abc123"
	sig := ed25519.Sign(priv, []byte(message))

	v := verifier{}
	// Truncated signature (wrong length) must be rejected outright, not
	// panic or silently pass through to ed25519.Verify with a mismatched
	// buffer size.
	if _, err := v.Verify(message, address, sig[:len(sig)-1]); err == nil {
		t.Fatal("expected an error for a truncated signature")
	}
	// Bit-flipped-but-correct-length signature must fail verification.
	corrupted := append([]byte(nil), sig...)
	corrupted[0] ^= 0xFF
	if _, err := v.Verify(message, address, corrupted); err == nil {
		t.Fatal("expected an error for a corrupted (but correctly sized) signature")
	}
}

func TestVerifierVerifyRejectsInvalidAddress(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := "RWA Platform admin login.\nNonce: abc123"
	sig := ed25519.Sign(priv, []byte(message))

	v := verifier{}
	if _, err := v.Verify(message, "not-a-valid-base58-address!!", sig); err == nil {
		t.Fatal("expected an error for a malformed address")
	}
}
