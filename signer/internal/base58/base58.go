// Package base58 implements the Bitcoin/Solana base58 alphabet.
//
// The signer needs it for one reason only: a Solana attestation binds three
// 32-byte account keys (cluster genesis hash, program id, config PDA) plus a
// 32-byte Vault authority, and an auditor comparing those against their own
// records, an explorer, or `solana address` sees base58 -- never hex. Showing
// only hex on the review screen would make the most security-critical part of
// the Solana domain unverifiable in practice.
//
// It is deliberately dependency-free: the signer runs air-gapped and every
// third-party package it pulls in is another thing that has to be trusted on
// the offline machine.
package base58

import (
	"fmt"
	"math/big"
	"strings"
)

// Alphabet is the standard base58 alphabet (no 0, O, I, l), shared by
// Bitcoin and Solana.
const Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var radix = big.NewInt(58)

// Encode renders b in base58. Leading zero bytes become leading '1's, which
// is what makes the all-zero 32-byte key render as Solana's familiar
// "11111111111111111111111111111111" system-program id.
func Encode(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}

	n := new(big.Int).SetBytes(b)
	mod := new(big.Int)
	// A base58 digit carries log2(58) ~= 5.86 bits, so 138/100 bytes-to-digits
	// is a safe upper bound on the output length.
	out := make([]byte, 0, len(b)*138/100+zeros+1)
	for n.Sign() > 0 {
		n.DivMod(n, radix, mod)
		out = append(out, Alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, Alphabet[0])
	}

	// The loop above emits least-significant digit first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// Decode parses a base58 string. It rejects an empty string and any
// character outside Alphabet rather than skipping it: a silently-ignored
// character in a pasted program id would decode to a different key than the
// one the operator believes they typed.
func Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("base58: empty string")
	}

	n := new(big.Int)
	for i, r := range s {
		idx := strings.IndexRune(Alphabet, r)
		if idx < 0 {
			return nil, fmt.Errorf("base58: invalid character %q at offset %d", r, i)
		}
		n.Mul(n, radix)
		n.Add(n, big.NewInt(int64(idx)))
	}

	zeros := 0
	for zeros < len(s) && s[zeros] == Alphabet[0] {
		zeros++
	}
	body := n.Bytes()
	out := make([]byte, zeros+len(body))
	copy(out[zeros:], body)
	return out, nil
}

// DecodePubkey parses a base58 Solana public key (or genesis hash) and
// requires it to be exactly 32 bytes.
func DecodePubkey(s string) ([32]byte, error) {
	var out [32]byte
	b, err := Decode(s)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("base58: %q decodes to %d bytes, want a 32-byte Solana public key", s, len(b))
	}
	copy(out[:], b)
	return out, nil
}
