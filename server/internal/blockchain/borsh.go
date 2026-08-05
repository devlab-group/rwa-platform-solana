package blockchain

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/mr-tron/base58"
)

// borshReader sequentially decodes exactly the primitive kinds this
// package's event schemas use, in Borsh's fixed layout (no length prefix,
// no padding, little-endian integers). Anchor events are plain Borsh
// structs, so a schema's declared field order is the wire order.
type borshReader struct {
	buf []byte
	pos int
}

func newBorshReader(buf []byte) *borshReader {
	return &borshReader{buf: buf}
}

func (r *borshReader) take(n int) ([]byte, error) {
	if n < 0 || r.pos+n > len(r.buf) {
		return nil, fmt.Errorf("blockchain: borsh: truncated (need %d bytes at offset %d, have %d)", n, r.pos, len(r.buf))
	}
	b := r.buf[r.pos : r.pos+n]
	r.pos += n
	return b, nil
}

// pubkey decodes a 32-byte Solana public key to its base58 string —
// case-preserved, NEVER lowercased, matching the frozen contract's
// addressing invariant.
func (r *borshReader) pubkey() (string, error) {
	b, err := r.take(32)
	if err != nil {
		return "", err
	}
	return base58.Encode(b), nil
}

// u8 decodes a single unsigned byte.
func (r *borshReader) u8() (uint64, error) {
	b, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return uint64(b[0]), nil
}

// boolean decodes a Borsh bool: exactly one byte, 0 or 1.
func (r *borshReader) boolean() (bool, error) {
	b, err := r.take(1)
	if err != nil {
		return false, err
	}
	if b[0] != 0 && b[0] != 1 {
		return false, fmt.Errorf("blockchain: borsh: invalid bool byte 0x%02x", b[0])
	}
	return b[0] == 1, nil
}

// u64String decodes an 8-byte little-endian unsigned integer to its
// decimal string, matching the EVM decoders' convention of stringifying
// big numbers.
func (r *borshReader) u64String() (string, error) {
	b, err := r.take(8)
	if err != nil {
		return "", err
	}
	return new(big.Int).SetUint64(binary.LittleEndian.Uint64(b)).String(), nil
}

// i64String decodes an 8-byte little-endian signed integer to its decimal
// string.
func (r *borshReader) i64String() (string, error) {
	b, err := r.take(8)
	if err != nil {
		return "", err
	}
	v := int64(binary.LittleEndian.Uint64(b))
	return big.NewInt(v).String(), nil
}

// hexBytes decodes a fixed n-byte array to a "0x"-prefixed lowercase hex
// string — matches the EVM decoders' convention for hashes/eth-addresses;
// unlike pubkey, these are NOT base58/case-sensitive identifiers.
func (r *borshReader) hexBytes(n int) (string, error) {
	b, err := r.take(n)
	if err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(b), nil
}
