package auth

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/mr-tron/base58"
)

// Verifier abstracts wallet-signature verification over the Solana ed25519
// wallet-standard signMessage primitive, so AdminChallengeService and
// compliance.ChallengeService can share one nonce/single-use/expiry/upsert
// implementation (see the frozen solana-auth-contract design doc). Every
// method operates on the WIRE address string (base58) — never a
// chain-specific typed address — so callers in package auth/compliance stay
// decoupled from the concrete verifier.
type Verifier interface {
	// ValidateAddress reports whether address is syntactically valid.
	ValidateAddress(address string) bool
	// NormalizeAddress returns address's canonical form. For Solana this is
	// the identity function — base58 is already canonical and, unlike hex,
	// is case-SIGNIFICANT, so it must never be case-folded. Both the
	// challenge's stored Address and every later lookup/comparison go
	// through this so a caller-supplied address in any valid casing/shape
	// still matches.
	NormalizeAddress(address string) string
	// Verify checks that sig is a valid signature over message from the
	// wallet identified by address's public key, returning the canonical
	// (NormalizeAddress-shaped) signer address on success. There is no
	// "recovery": address IS the ed25519 public key, so Verify either
	// confirms sig was produced by that exact key (and echoes address back)
	// or errors.
	Verify(message, address string, sig []byte) (string, error)
}

// NewVerifier constructs the Verifier implementation.
func NewVerifier() Verifier {
	return verifier{}
}

// verifier implements the frozen Solana wallet-auth contract: the
// wallet's Wallet-Standard signMessage produces a raw 64-byte ed25519
// signature over the UTF-8 challenge message bytes verbatim (no EIP-191-style
// prefixing — Solana has no equivalent convention), and the "address" IS the
// base58-encoded ed25519 public key, so verification needs no signer
// recovery: it directly checks the signature against that key.
type verifier struct{}

func (verifier) ValidateAddress(address string) bool {
	pub, err := base58.Decode(address)
	return err == nil && len(pub) == ed25519.PublicKeySize
}

// NormalizeAddress is the identity function for Solana: base58 is already
// canonical and, unlike hex, distinguishes case (upper/lowercase letters are
// different symbols in the base58 alphabet), so folding case here would
// silently corrupt a valid address into a different one.
func (verifier) NormalizeAddress(address string) string { return address }

func (verifier) Verify(message, address string, sig []byte) (string, error) {
	pub, err := base58.Decode(address)
	if err != nil {
		return "", fmt.Errorf("auth: invalid address %q: %w", address, err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("auth: address %q decodes to %d bytes, want %d", address, len(pub), ed25519.PublicKeySize)
	}
	if len(sig) != ed25519.SignatureSize {
		return "", fmt.Errorf("auth: signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(message), sig) {
		return "", errors.New("auth: ed25519 signature verification failed")
	}
	return address, nil
}
