package blockchain

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/mr-tron/base58"
)

func mustPubkeyBytes(t *testing.T, b58 string) [32]byte {
	t.Helper()
	b, err := base58.Decode(b58)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 32 {
		t.Fatalf("%q decodes to %d bytes, want 32", b58, len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

// TestCompileLegacyMessageMatchesSoldersReference reproduces, byte-for-byte,
// a Message solders (Message.new_with_blockhash) compiled for the EXACT
// same fee payer, accounts, and instruction data this package's set_status
// writer builds — authority and payer are the SAME key (this deployment's
// single compliance hot key plays both roles), which is exactly the
// account-deduplication case CompileLegacyMessage's doc comment calls out.
// Generating this vector (like the PDA one in pda_test.go) is what actually
// proves the account-ordering/dedup logic against an independent
// implementation, not just this package's own self-consistency.
func TestCompileLegacyMessageMatchesSoldersReference(t *testing.T) {
	feePayer := mustPubkeyBytes(t, "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi")
	registry := mustPubkeyBytes(t, "GvopmZw6MC3AxUXwqNw3qHZBoazyKM3tBmtpBp8JaF3m")
	wallet := mustPubkeyBytes(t, "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR")
	record := mustPubkeyBytes(t, "E5ba8VGJwm8U8Jx3wUJWPfijDbQvYgxjTAuiQTFvbNNu")
	systemProgram := mustPubkeyBytes(t, "11111111111111111111111111111111")
	programID := mustPubkeyBytes(t, "SuppLyCtR1111111111111111111111111111111111")
	blockhash := "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8" // any valid 32-byte base58 value works as a stand-in hash

	data := append([]byte{181, 184, 224, 203, 193, 29, 177, 224}, byte(1))
	data = append(data, 0, 0, 0, 0, 0, 0, 0, 0) // valid_until = 0, little-endian u64

	instr := Instruction{
		ProgramID: programID,
		Accounts: []AccountMeta{
			{Pubkey: registry, IsSigner: false, IsWritable: false},
			{Pubkey: feePayer, IsSigner: true, IsWritable: false}, // authority
			{Pubkey: wallet, IsSigner: false, IsWritable: false},
			{Pubkey: record, IsSigner: false, IsWritable: true},
			{Pubkey: feePayer, IsSigner: true, IsWritable: true}, // payer (same key as authority)
			{Pubkey: systemProgram, IsSigner: false, IsWritable: false},
		},
		Data: data,
	}

	got, err := CompileLegacyMessage(feePayer, blockhash, []Instruction{instr})
	if err != nil {
		t.Fatalf("CompileLegacyMessage: %v", err)
	}

	want := "010004060101010101010101010101010101010101010101010101010101010101010101c25557d2165e8f73e6d13e14e5edf7d4c0627bba98fe071f33d477a3560fee4a0000000000000000000000000000000000000000000000000000000000000000020202020202020202020202020202020202020202020202020202020202020206a33fbda42deadda46f83f11ca308489dade56631192daca9b26f4800000000eca807c71cf444ea263dee3542ae5125801755dab64d885186024eb9f9aba8f0030303030303030303030303030303030303030303030303030303030303030301040605000301000211b5b8e0cbc11db1e0010000000000000000"
	if gotHex := hex.EncodeToString(got); gotHex != want {
		t.Errorf("compiled message =\n%s\nwant (solders reference)\n%s", gotHex, want)
	}
}

// TestCompileLegacyMessageFeePayerStaysFirstEvenWhenSortedAfterAnotherSigner
// is the second solders-cross-checked vector: this is what actually caught
// (during development) that within-bucket ordering is sorted-by-bytes, NOT
// first-seen — a naive "sort everything including feePayer" implementation
// would have passed the OTHER vector (registry/wallet/systemProgram/
// programID all happen to sort consistently either way there) but fails
// this one, where feePayer's own bytes sort AFTER another writable signer's.
func TestCompileLegacyMessageFeePayerStaysFirstEvenWhenSortedAfterAnotherSigner(t *testing.T) {
	feePayer := mustPubkeyBytes(t, "GvopmZw6MC3AxUXwqNw3qHZBoazyKM3tBmtpBp8JaF3m") // 0xec... — sorts AFTER the other signer below
	otherSigner := mustPubkeyBytes(t, "11111111111111111111111111111111")          // 0x00... — would sort first if feePayer weren't pinned
	programID := mustPubkeyBytes(t, "SuppLyCtR1111111111111111111111111111111111")

	instr := Instruction{
		ProgramID: programID,
		Accounts:  []AccountMeta{{Pubkey: otherSigner, IsSigner: true, IsWritable: true}},
		Data:      []byte{1, 2, 3},
	}
	got, err := CompileLegacyMessage(feePayer, "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8", []Instruction{instr})
	if err != nil {
		t.Fatal(err)
	}
	// solders reference: header {numRequiredSignatures:2, numReadonlySigned:0,
	// numReadonlyUnsigned:1}, account_keys = [feePayer, otherSigner, programID].
	if got[0] != 2 || got[1] != 0 || got[2] != 1 {
		t.Fatalf("header = %v, want [2,0,1]", got[0:3])
	}
	if got[3] != 3 {
		t.Fatalf("account_keys count = %d, want 3", got[3])
	}
	accountKeys := got[4 : 4+3*32]
	if !bytesEqual(accountKeys[0:32], feePayer[:]) {
		t.Error("account_keys[0] must be feePayer, even though its bytes sort after otherSigner's")
	}
	if !bytesEqual(accountKeys[32:64], otherSigner[:]) {
		t.Error("account_keys[1] must be otherSigner")
	}
	if !bytesEqual(accountKeys[64:96], programID[:]) {
		t.Error("account_keys[2] must be programID")
	}
}

// TestCompileLegacyMessageAccountOrderingAndDedup covers the properties the
// solders vector above pins for one specific case: feePayer is always
// index 0 (writable signer), and a pubkey referenced with DIFFERENT
// signer/writable flags across occurrences ends up with the union
// (most-permissive) of them, appearing exactly once.
func TestCompileLegacyMessageAccountOrderingAndDedup(t *testing.T) {
	feePayer := mustPubkeyBytes(t, "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi")
	other := mustPubkeyBytes(t, "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR")
	programID := mustPubkeyBytes(t, "SuppLyCtR1111111111111111111111111111111111")

	instr := Instruction{
		ProgramID: programID,
		// "other" appears once as read-only, once as writable — must end
		// up writable (the union) and appear only once in account_keys.
		Accounts: []AccountMeta{
			{Pubkey: other, IsSigner: false, IsWritable: false},
			{Pubkey: other, IsSigner: false, IsWritable: true},
		},
		Data: []byte{1, 2, 3},
	}
	msg, err := CompileLegacyMessage(feePayer, "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8", []Instruction{instr})
	if err != nil {
		t.Fatal(err)
	}
	// header: numRequiredSignatures=1, numReadonlySigned=0, numReadonlyUnsigned=1 (programID only — "other" is writable)
	if msg[0] != 1 || msg[1] != 0 || msg[2] != 1 {
		t.Fatalf("header = %v, want [1,0,1]", msg[0:3])
	}
	// account_keys count (shortvec) = 3: feePayer, other, programID
	if msg[3] != 3 {
		t.Fatalf("account_keys count = %d, want 3", msg[3])
	}
	accountKeys := msg[4 : 4+3*32]
	if !bytesEqual(accountKeys[0:32], feePayer[:]) {
		t.Error("account_keys[0] must be feePayer")
	}
	if !bytesEqual(accountKeys[32:64], other[:]) {
		t.Error("account_keys[1] must be the deduplicated 'other' account (writable, appearing once)")
	}
	if !bytesEqual(accountKeys[64:96], programID[:]) {
		t.Error("account_keys[2] must be programID")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestCompileLegacyMessageRejectsNoInstructions(t *testing.T) {
	feePayer := mustPubkeyBytes(t, "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi")
	if _, err := CompileLegacyMessage(feePayer, "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8", nil); err == nil {
		t.Fatal("expected an error for zero instructions")
	}
}

func TestCompileLegacyMessageRejectsMalformedBlockhash(t *testing.T) {
	feePayer := mustPubkeyBytes(t, "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi")
	instr := Instruction{ProgramID: feePayer, Data: []byte{1}}
	if _, err := CompileLegacyMessage(feePayer, "not-a-blockhash", []Instruction{instr}); err == nil {
		t.Fatal("expected an error for a malformed blockhash")
	}
}

// TestSignTransactionProducesVerifiableSignature checks the wire framing
// (shortvec(1) + 64-byte signature + message) and that the signature
// actually verifies against the message under the signer's public key —
// the property sendTransaction's own preflight simulation (and the
// on-chain runtime) checks before doing anything else.
func TestSignTransactionProducesVerifiableSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var feePayer [32]byte
	copy(feePayer[:], pub)

	instr := Instruction{ProgramID: feePayer, Data: []byte{9, 9, 9}}
	msg, err := CompileLegacyMessage(feePayer, "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8", []Instruction{instr})
	if err != nil {
		t.Fatal(err)
	}

	base64Tx, sig, err := SignTransaction(msg, priv)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(base64Tx)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if raw[0] != 1 {
		t.Fatalf("signature count shortvec = %d, want 1", raw[0])
	}
	sigBytes := raw[1:65]
	if base58.Encode(sigBytes) != sig {
		t.Error("returned signature doesn't match the bytes embedded in the wire transaction")
	}
	if !bytesEqual(raw[65:], msg) {
		t.Error("message bytes after the signature don't match the compiled message")
	}
	if !ed25519.Verify(pub, msg, sigBytes) {
		t.Error("signature does not verify against the message under the signer's public key")
	}
}

// TestSignTransactionRejectsSignerNotFeePayer pins the invariant that
// SignTransaction must reject a signer whose public key is not
// the compiled Message's account_keys[0] (the fee payer), rather than
// silently emitting a transaction the runtime would reject anyway for a
// missing feePayer signature.
func TestSignTransactionRejectsSignerNotFeePayer(t *testing.T) {
	feePayerPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongSigner, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	var feePayer [32]byte
	copy(feePayer[:], feePayerPub)
	instr := Instruction{ProgramID: feePayer, Data: []byte{9, 9, 9}}
	msg, err := CompileLegacyMessage(feePayer, "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8", []Instruction{instr})
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := SignTransaction(msg, wrongSigner); err == nil {
		t.Fatal("expected an error when signer's public key does not match account_keys[0]")
	}
}

func TestSignTransactionRejectsWrongSizedKey(t *testing.T) {
	if _, _, err := SignTransaction([]byte("msg"), []byte("too-short")); err == nil {
		t.Fatal("expected an error for a malformed signer key")
	}
}

func TestEncodeShortVecLenKnownValues(t *testing.T) {
	cases := map[int][]byte{
		0:     {0x00},
		1:     {0x01},
		127:   {0x7f},
		128:   {0x80, 0x01},
		16384: {0x80, 0x80, 0x01},
	}
	for n, want := range cases {
		got := encodeShortVecLen(n)
		if !bytesEqual(got, want) {
			t.Errorf("encodeShortVecLen(%d) = %x, want %x", n, got, want)
		}
	}
}
