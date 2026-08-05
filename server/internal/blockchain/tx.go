// Legacy Solana transaction assembly: compiling a Message from a fee payer
// + a set of instructions, and signing/serializing the resulting
// Transaction for sendTransaction. This is intentionally minimal — legacy
// (non-versioned) transactions only, no address-lookup-table support, no
// multi-signer compilation beyond what CompileLegacyMessage's account-
// ordering already handles generically — everything this codebase's first
// Solana-broadcasting caller (internal/compliance's set_status writer)
// needs and nothing more, to avoid pulling in a heavyweight Solana SDK
// dependency (matching client.go's existing minimal-RPC-client rationale).
package blockchain

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"

	"github.com/mr-tron/base58"
)

// AccountMeta describes one account an instruction references, mirroring
// Solana's own AccountMeta: which account, and whether THIS instruction
// needs it to sign / be writable. The same pubkey can appear in multiple
// instructions (or multiple times within one) with different flags —
// CompileLegacyMessage takes the union (most permissive) of every
// occurrence when it deduplicates into the Message's single account list.
type AccountMeta struct {
	Pubkey     [32]byte
	IsSigner   bool
	IsWritable bool
}

// Instruction is one instruction to compile into a Message: the program to
// invoke, the accounts it references in the EXACT order the program
// expects (this order is preserved verbatim in the compiled instruction's
// account-index list — only the Message's top-level account_keys list gets
// reordered/deduplicated), and the opaque instruction data (an Anchor
// 8-byte discriminator + Borsh-encoded args, for this codebase's use).
type Instruction struct {
	ProgramID [32]byte
	Accounts  []AccountMeta
	Data      []byte
}

// accountFlags accumulates the union of every signer/writable requirement
// observed for one pubkey across every instruction being compiled — a
// pubkey referenced as read-only in one place and writable in another must
// end up writable in the compiled Message, since the runtime's per-account
// permissions are message-wide, not per-instruction.
type accountFlags struct {
	signer   bool
	writable bool
}

// CompileLegacyMessage assembles a legacy (non-versioned) Solana Message
// from feePayer + instrs, following Solana's standard account ordering —
// [writable signers][readonly signers][writable non-signers][readonly
// non-signers], each group sorted by raw pubkey bytes ascending (the
// canonical solana-sdk/solders behavior — cross-checked in tx_test.go;
// insertion/first-seen order is a tempting but WRONG guess that still
// produces a protocol-valid transaction, just not the one every other tool
// reconstructing/verifying it would produce) — and de-duplicating repeated
// pubkeys (including a program id that is ALSO referenced as a plain
// account, and feePayer appearing again inside an instruction's own
// account list, e.g. as this codebase's compliance authority AND payer are
// the same key — see internal/compliance's status writer). feePayer
// is always account index 0 and always signer+writable, regardless of its
// own byte value or whether any instruction explicitly marks it so (a
// transaction's fee payer must sign and pay, by definition, and Solana's
// own message compiler enforces the same rule — confirmed against a case
// where feePayer's bytes sort after another writable signer's and it still
// won index 0).
//
// recentBlockhash is base58, exactly as returned by RPCClient.
// GetLatestBlockhash.
//
// The resulting bytes are the Message wire format the runtime hashes and
// verifies signatures over — see SignTransaction for turning this into a
// broadcastable Transaction.
func CompileLegacyMessage(feePayer [32]byte, recentBlockhash string, instrs []Instruction) ([]byte, error) {
	if len(instrs) == 0 {
		return nil, errors.New("blockchain: CompileLegacyMessage: at least one instruction is required")
	}
	blockhashBytes, err := base58.Decode(recentBlockhash)
	if err != nil {
		return nil, fmt.Errorf("blockchain: decoding recent blockhash %q: %w", recentBlockhash, err)
	}
	if len(blockhashBytes) != 32 {
		return nil, fmt.Errorf("blockchain: recent blockhash %q decodes to %d bytes, want 32", recentBlockhash, len(blockhashBytes))
	}

	var order [][32]byte
	seen := map[[32]byte]bool{}
	meta := map[[32]byte]*accountFlags{}
	ensure := func(pk [32]byte, signer, writable bool) {
		if !seen[pk] {
			seen[pk] = true
			order = append(order, pk)
			meta[pk] = &accountFlags{}
		}
		f := meta[pk]
		if signer {
			f.signer = true
		}
		if writable {
			f.writable = true
		}
	}

	ensure(feePayer, true, true)
	for _, instr := range instrs {
		for _, a := range instr.Accounts {
			ensure(a.Pubkey, a.IsSigner, a.IsWritable)
		}
		// A program id referenced only via Instruction.ProgramID (the
		// common case — it is not usually ALSO passed as a plain account
		// argument) still needs an account_keys entry so
		// program_id_index can point at it; ensure is a no-op for a
		// pubkey already seen with equal-or-greater permissions (e.g. if
		// some instruction elsewhere also legitimately lists it as a
		// plain readonly account).
		ensure(instr.ProgramID, false, false)
	}

	var writableSigners, readonlySigners, writableNon, readonlyNon [][32]byte
	for _, pk := range order {
		if pk == feePayer {
			continue // placed first in writableSigners explicitly below, never sorted away from index 0
		}
		f := meta[pk]
		switch {
		case f.signer && f.writable:
			writableSigners = append(writableSigners, pk)
		case f.signer && !f.writable:
			readonlySigners = append(readonlySigners, pk)
		case !f.signer && f.writable:
			writableNon = append(writableNon, pk)
		default:
			readonlyNon = append(readonlyNon, pk)
		}
	}
	// Within each of the 4 buckets, the canonical Solana message compiler
	// (solana-sdk's Message::new_with_blockhash, and solders — cross-checked
	// in tx_test.go) sorts by raw pubkey bytes ascending, NOT first-seen/
	// insertion order — confirmed empirically during development (insertion
	// order produces a protocol-valid but non-canonical account_keys list,
	// which every other tool reconstructing/verifying this transaction would
	// disagree with). feePayer is the sole exception: always index 0,
	// regardless of its own byte value, confirmed against a case where
	// feePayer's bytes sort AFTER another writable signer's.
	pkLess := func(a, b [32]byte) bool { return bytes.Compare(a[:], b[:]) < 0 }
	sortPubkeys(writableSigners, pkLess)
	sortPubkeys(readonlySigners, pkLess)
	sortPubkeys(writableNon, pkLess)
	sortPubkeys(readonlyNon, pkLess)

	accountKeys := make([][32]byte, 0, len(order))
	accountKeys = append(accountKeys, feePayer)
	accountKeys = append(accountKeys, writableSigners...)
	accountKeys = append(accountKeys, readonlySigners...)
	accountKeys = append(accountKeys, writableNon...)
	accountKeys = append(accountKeys, readonlyNon...)

	index := make(map[[32]byte]int, len(accountKeys))
	for i, pk := range accountKeys {
		index[pk] = i
	}

	numRequiredSignatures := 1 + len(writableSigners) + len(readonlySigners) // +1 for feePayer
	if numRequiredSignatures > 255 || len(accountKeys) > 255 {
		return nil, errors.New("blockchain: CompileLegacyMessage: too many accounts (message header fields are single bytes)")
	}

	var buf bytes.Buffer
	// MessageHeader: numRequiredSignatures, numReadonlySignedAccounts,
	// numReadonlyUnsignedAccounts.
	buf.WriteByte(byte(numRequiredSignatures))
	buf.WriteByte(byte(len(readonlySigners)))
	buf.WriteByte(byte(len(readonlyNon)))

	buf.Write(encodeShortVecLen(len(accountKeys)))
	for _, pk := range accountKeys {
		buf.Write(pk[:])
	}

	buf.Write(blockhashBytes)

	buf.Write(encodeShortVecLen(len(instrs)))
	for _, instr := range instrs {
		progIdx, ok := index[instr.ProgramID]
		if !ok {
			return nil, fmt.Errorf("blockchain: CompileLegacyMessage: program id %s missing from compiled account list (internal error)", base58.Encode(instr.ProgramID[:]))
		}
		buf.WriteByte(byte(progIdx))

		accIdx := make([]byte, len(instr.Accounts))
		for i, a := range instr.Accounts {
			idx, ok := index[a.Pubkey]
			if !ok {
				return nil, fmt.Errorf("blockchain: CompileLegacyMessage: account %s missing from compiled account list (internal error)", base58.Encode(a.Pubkey[:]))
			}
			accIdx[i] = byte(idx)
		}
		buf.Write(encodeShortVecLen(len(accIdx)))
		buf.Write(accIdx)

		buf.Write(encodeShortVecLen(len(instr.Data)))
		buf.Write(instr.Data)
	}

	return buf.Bytes(), nil
}

// sortPubkeys sorts pks in place by raw byte value ascending using less
// (bytes.Compare), matching the canonical Solana message compiler's
// within-bucket ordering — see CompileLegacyMessage's doc comment.
func sortPubkeys(pks [][32]byte, less func(a, b [32]byte) bool) {
	sort.Slice(pks, func(i, j int) bool { return less(pks[i], pks[j]) })
}

// encodeShortVecLen encodes n as Solana's "compact-u16" / shortvec length
// prefix: 7 payload bits per byte, high bit set on every byte except the
// last (LEB128-style, capped at values that fit — n is always a small
// count in this codebase, never anywhere near the encoding's full range).
func encodeShortVecLen(n int) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n == 0 {
			out = append(out, b)
			return out
		}
		out = append(out, b|0x80)
	}
}

// decodeShortVecLen is the decoding counterpart of encodeShortVecLen: reads
// a compact-u16/shortvec length prefix from the start of buf, returning the
// decoded value and how many bytes it occupied.
func decodeShortVecLen(buf []byte) (n int, consumed int, err error) {
	var shift uint
	for i, b := range buf {
		n |= int(b&0x7f) << shift
		consumed = i + 1
		if b&0x80 == 0 {
			return n, consumed, nil
		}
		shift += 7
		if shift > 21 { // generous headroom over this codebase's account-count range
			return 0, 0, errors.New("blockchain: decodeShortVecLen: value too large")
		}
	}
	return 0, 0, errors.New("blockchain: decodeShortVecLen: truncated")
}

// messageFeePayer extracts account_keys[0] (the fee payer — always index 0
// in a Message CompileLegacyMessage produced, per its own doc comment) from
// message's compiled wire bytes: a 3-byte header, then a shortvec-encoded
// account_keys count, then that many 32-byte pubkeys back to back —
// account_keys[0] is simply the first pubkey right after the count.
func messageFeePayer(message []byte) ([]byte, error) {
	const headerLen = 3
	if len(message) < headerLen {
		return nil, errors.New("blockchain: message shorter than the 3-byte header")
	}
	count, consumed, err := decodeShortVecLen(message[headerLen:])
	if err != nil {
		return nil, fmt.Errorf("decoding account_keys length: %w", err)
	}
	if count < 1 {
		return nil, errors.New("blockchain: message has zero account_keys entries")
	}
	start := headerLen + consumed
	if len(message) < start+32 {
		return nil, errors.New("blockchain: message truncated before account_keys[0]")
	}
	return message[start : start+32], nil
}

// SignTransaction signs message (the bytes CompileLegacyMessage returned)
// with signer and assembles the full wire Transaction — a shortvec-
// prefixed array of signatures followed by the message bytes verbatim —
// then base64-encodes it for SendTransaction/RPCClient.SendTransaction.
// signer's public key MUST be the Message's account_keys[0] (the fee
// payer) — enforced below by decoding it straight out of message, rather
// than trusting the caller — this codebase's only caller (the compliance
// status writer) always compiles with exactly one required signature, so
// this only ever produces a single-signature transaction; it does not
// attempt to support multi-signer transactions. A future caller that
// compiled a message requiring more than one signer would now fail loudly
// here instead of silently emitting a transaction the runtime rejects for
// a missing signature.
//
// Returns both the base64 wire transaction and the signature's own base58
// encoding — the latter IS the transaction's signature/id, exactly what
// sendTransaction itself would echo back on success (Solana transaction
// ids are simply the fee payer's signature, not a separately hashed
// value), so a caller can record it immediately without waiting on the
// RPC round trip.
func SignTransaction(message []byte, signer ed25519.PrivateKey) (base64Tx string, signature string, err error) {
	if len(signer) != ed25519.PrivateKeySize {
		return "", "", fmt.Errorf("blockchain: SignTransaction: signer key is %d bytes, want %d", len(signer), ed25519.PrivateKeySize)
	}
	// numRequiredSignatures is the message header's first byte (see
	// messageFeePayer's doc comment on the wire layout). This function only
	// ever writes exactly one signature below, so a message compiled with
	// more than one required signer must fail loudly HERE — not silently
	// emit a transaction the runtime rejects for a missing signature. The
	// doc comment above already claimed this was enforced; it was not,
	// until this check.
	if len(message) < 1 {
		return "", "", errors.New("blockchain: SignTransaction: message shorter than the 3-byte header")
	}
	if message[0] != 1 {
		return "", "", fmt.Errorf("blockchain: SignTransaction: message requires %d signatures, but this function only ever produces exactly 1 (single-signer transactions only)", message[0])
	}
	feePayer, err := messageFeePayer(message)
	if err != nil {
		return "", "", fmt.Errorf("blockchain: SignTransaction: reading account_keys[0]: %w", err)
	}
	pub, _ := signer.Public().(ed25519.PublicKey)
	if !bytes.Equal(pub, feePayer) {
		return "", "", fmt.Errorf("blockchain: SignTransaction: signer public key %s does not match message account_keys[0] (fee payer) %s", base58.Encode(pub), base58.Encode(feePayer))
	}
	sig := ed25519.Sign(signer, message)

	var buf bytes.Buffer
	buf.Write(encodeShortVecLen(1)) // exactly one signature — see doc comment
	buf.Write(sig)
	buf.Write(message)

	return base64.StdEncoding.EncodeToString(buf.Bytes()), base58.Encode(sig), nil
}
