package api

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/mr-tron/base58"
)

// decodeWalletSignature decodes the wire-format wallet signature per the
// frozen solana-auth-contract: Solana Wallet-Standard signMessage
// signatures arrive base58-encoded (see bs58.encode(sigBytes) in the client
// contract). Shared by the admin (createSession) and investor
// (verifyChallenge) wallet-auth endpoints.
func decodeWalletSignature(s string) ([]byte, error) {
	return base58.Decode(s)
}

func hexToBytes32(s string) ([32]byte, error) {
	var out [32]byte
	trimmed := strings.TrimPrefix(s, "0x")
	if len(trimmed) != 64 {
		return out, fmt.Errorf("expected 32-byte hex (64 chars after 0x), got %d chars", len(trimmed))
	}
	b, err := hex.DecodeString(trimmed)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}
