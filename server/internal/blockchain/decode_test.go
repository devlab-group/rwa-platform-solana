package blockchain

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"github.com/mr-tron/base58"
)

// --- golden-vector test helpers ---

// pubkeyBytes builds a distinguishable 32-byte "pubkey" (fill byte
// repeated) and returns both its raw bytes and base58 encoding, so tests
// can assert Decode's output against the same encoding this package uses.
func pubkeyBytes(fill byte) (raw []byte, b58 string) {
	raw = make([]byte, 32)
	for i := range raw {
		raw[i] = fill
	}
	return raw, base58.Encode(raw)
}

func hexBytesN(fill byte, n int) (raw []byte, hexStr string) {
	raw = make([]byte, n)
	for i := range raw {
		raw[i] = fill
	}
	return raw, "0x" + hex.EncodeToString(raw)
}

func leU64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

// buildPayload concatenates disc with every part, simulating one Borsh-
// encoded Anchor event body.
func buildPayload(disc [8]byte, parts ...[]byte) []byte {
	out := append([]byte{}, disc[:]...)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// programDataLine formats payload the way an Anchor emit! log line looks,
// so decodeProgramDataLine-adjacent logic (strings.CutPrefix + base64) is
// exercised too, not just Decode directly.
func programDataLine(payload []byte) string {
	return programDataPrefix + base64.StdEncoding.EncodeToString(payload)
}

// framedLogLines wraps inner with the "Program <program> invoke [1]" /
// "Program <program> success" framing a real Solana transaction log has for
// one top-level instruction invoking program — Indexer.ingestTransaction
// attributes a "Program data:" line to whichever program is on TOP of the
// invocation stack when the line appears, not simply to
// whichever program is being scanned, so a fixture's data lines must be
// wrapped in this framing to be attributed to program at all.
func framedLogLines(program string, inner ...string) []string {
	lines := make([]string, 0, len(inner)+2)
	lines = append(lines, "Program "+program+" invoke [1]")
	lines = append(lines, inner...)
	lines = append(lines, "Program "+program+" success")
	return lines
}

func TestDecodePurchased(t *testing.T) {
	disc := [8]byte{20, 112, 33, 232, 177, 248, 215, 233}
	buyerRaw, buyerB58 := pubkeyBytes(0x01)
	recipientRaw, recipientB58 := pubkeyBytes(0x02)
	payload := buildPayload(disc, buyerRaw, recipientRaw, leU64(12345), leU64(6789))

	line := programDataLine(payload)
	rest, ok := strings.CutPrefix(line, programDataPrefix)
	if !ok {
		t.Fatal("expected programDataPrefix")
	}
	decoded, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	name, data, ok, err := Decode(RoleVault, decoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !ok {
		t.Fatal("Decode: ok=false, want true")
	}
	if name != "Purchased" {
		t.Errorf("name = %q, want Purchased", name)
	}
	want := map[string]any{
		"buyer": buyerB58, "recipient": recipientB58,
		"tokenAmount": "12345", "quoteAmount": "6789",
	}
	if !reflect.DeepEqual(data, want) {
		t.Errorf("data = %#v, want %#v", data, want)
	}
}

func TestDecodeRedemptionRequested(t *testing.T) {
	disc := [8]byte{245, 155, 98, 131, 210, 25, 137, 146}
	beneficiaryRaw, beneficiaryB58 := pubkeyBytes(0x03)
	payload := buildPayload(disc, leU64(1), beneficiaryRaw, leU64(1000), leU64(950), leU64(1750000000))

	name, data, ok, err := Decode(RoleRedemption, payload)
	if err != nil || !ok {
		t.Fatalf("Decode: ok=%v err=%v", ok, err)
	}
	if name != "RedemptionRequested" {
		t.Errorf("name = %q, want RedemptionRequested", name)
	}
	want := map[string]any{
		"id": "1", "beneficiary": beneficiaryB58,
		"rwaAmount": "1000", "quoteAmount": "950", "createdAt": "1750000000",
	}
	if !reflect.DeepEqual(data, want) {
		t.Errorf("data = %#v, want %#v", data, want)
	}
}

func TestDecodeStatusChanged(t *testing.T) {
	disc := [8]byte{146, 235, 222, 125, 145, 246, 34, 240}
	accountRaw, accountB58 := pubkeyBytes(0x04)
	authorityRaw, authorityB58 := pubkeyBytes(0x05)
	payload := buildPayload(disc, accountRaw, []byte{1}, []byte{2}, leU64(0), leU64(1800000000), authorityRaw)

	name, data, ok, err := Decode(RoleCompliance, payload)
	if err != nil || !ok {
		t.Fatalf("Decode: ok=%v err=%v", ok, err)
	}
	if name != "StatusChanged" {
		t.Errorf("name = %q, want StatusChanged", name)
	}
	want := map[string]any{
		"account": accountB58, "previousStatus": uint(1), "newStatus": uint(2),
		"previousValidUntil": "0", "newValidUntil": "1800000000", "authority": authorityB58,
	}
	if !reflect.DeepEqual(data, want) {
		t.Errorf("data = %#v, want %#v", data, want)
	}
}

func TestDecodeMinted(t *testing.T) {
	disc := [8]byte{174, 131, 21, 57, 88, 117, 114, 121}
	recordKeyRaw, recordKeyHex := hexBytesN(0xAB, 32)
	digestRaw, digestHex := hexBytesN(0xCD, 32)
	vaultRaw, vaultB58 := pubkeyBytes(0x06)
	nonceRaw, nonceHex := hexBytesN(0xEF, 32)
	payload := buildPayload(disc, recordKeyRaw, digestRaw, vaultRaw, leU64(500000), nonceRaw)

	name, data, ok, err := Decode(RoleSupplyController, payload)
	if err != nil || !ok {
		t.Fatalf("Decode: ok=%v err=%v", ok, err)
	}
	if name != "Minted" {
		t.Errorf("name = %q, want Minted", name)
	}
	want := map[string]any{
		"recordKey": recordKeyHex, "metadataDigest": digestHex, "vault": vaultB58,
		"amount": "500000", "nonce": nonceHex,
	}
	if !reflect.DeepEqual(data, want) {
		t.Errorf("data = %#v, want %#v", data, want)
	}
}

func TestDecodeRoleChanged(t *testing.T) {
	disc := [8]byte{85, 88, 130, 5, 125, 143, 206, 240}
	previousRaw, previousB58 := pubkeyBytes(0x07)
	newValueRaw, newValueB58 := pubkeyBytes(0x08)
	byRaw, byB58 := pubkeyBytes(0x09)
	payload := buildPayload(disc, []byte{1}, previousRaw, newValueRaw, byRaw)

	name, data, ok, err := Decode(RoleVault, payload)
	if err != nil || !ok {
		t.Fatalf("Decode: ok=%v err=%v", ok, err)
	}
	if name != "RoleChanged" {
		t.Errorf("name = %q, want RoleChanged", name)
	}
	want := map[string]any{
		"role": uint(1), "previous": previousB58, "newValue": newValueB58, "by": byB58,
	}
	if !reflect.DeepEqual(data, want) {
		t.Errorf("data = %#v, want %#v", data, want)
	}
}

func TestDecodeAuditorChanged(t *testing.T) {
	disc := [8]byte{161, 37, 137, 138, 84, 145, 157, 4}
	previousRaw, previousHex := hexBytesN(0x11, 20)
	newAuditorRaw, newAuditorHex := hexBytesN(0x22, 20)
	byRaw, byB58 := pubkeyBytes(0x0A)
	payload := buildPayload(disc, previousRaw, newAuditorRaw, byRaw)

	name, data, ok, err := Decode(RoleSupplyController, payload)
	if err != nil || !ok {
		t.Fatalf("Decode: ok=%v err=%v", ok, err)
	}
	if name != "AuditorChanged" {
		t.Errorf("name = %q, want AuditorChanged", name)
	}
	want := map[string]any{
		"previous": previousHex, "newAuditor": newAuditorHex, "by": byB58,
	}
	if !reflect.DeepEqual(data, want) {
		t.Errorf("data = %#v, want %#v", data, want)
	}
}

// TestDecodeComplianceFinalizedRenamed proves the compliance/supply-
// controller "Finalized" name collision is disambiguated per the frozen
// contract.
func TestDecodeFinalizedNameDisambiguation(t *testing.T) {
	disc := [8]byte{4, 77, 242, 80, 20, 152, 247, 252}
	byRaw, byB58 := pubkeyBytes(0x0B)

	name, data, ok, err := Decode(RoleCompliance, buildPayload(disc, byRaw))
	if err != nil || !ok {
		t.Fatalf("Decode (compliance): ok=%v err=%v", ok, err)
	}
	if name != "ComplianceFinalized" {
		t.Errorf("compliance Finalized name = %q, want ComplianceFinalized", name)
	}
	if !reflect.DeepEqual(data, map[string]any{"by": byB58}) {
		t.Errorf("compliance Finalized data = %#v", data)
	}

	supplyRaw1, supplyB581 := pubkeyBytes(0x0C)
	supplyRaw2, supplyB582 := pubkeyBytes(0x0D)
	supplyRaw3, supplyB583 := pubkeyBytes(0x0E)
	supplyRaw4, supplyB584 := pubkeyBytes(0x0F)
	supplyRaw5, supplyB585 := pubkeyBytes(0x10)
	supplyRaw6, supplyB586 := pubkeyBytes(0x11)
	name2, data2, ok2, err2 := Decode(RoleSupplyController, buildPayload(disc, supplyRaw1, supplyRaw2, supplyRaw3, supplyRaw4, supplyRaw5, supplyRaw6))
	if err2 != nil || !ok2 {
		t.Fatalf("Decode (supply): ok=%v err=%v", ok2, err2)
	}
	if name2 != "SupplyFinalized" {
		t.Errorf("supply Finalized name = %q, want SupplyFinalized", name2)
	}
	want2 := map[string]any{
		"supply": supplyB581, "vault": supplyB582, "escrow": supplyB583,
		"registry": supplyB584, "strategy": supplyB585, "mint": supplyB586,
	}
	if !reflect.DeepEqual(data2, want2) {
		t.Errorf("supply Finalized data = %#v, want %#v", data2, want2)
	}
}

// TestDecodeUnknownDiscriminatorSkipped proves an unrecognized (garbage)
// discriminator returns ok=false, err=nil — not an error — so the indexer
// skips it rather than aborting.
func TestDecodeUnknownDiscriminatorSkipped(t *testing.T) {
	garbage := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x99, 0x99}
	name, data, ok, err := Decode(RoleVault, garbage)
	if err != nil {
		t.Fatalf("Decode(garbage): unexpected error %v", err)
	}
	if ok {
		t.Fatalf("Decode(garbage): ok=true, want false (name=%q data=%v)", name, data)
	}
}

// TestDecodeTruncatedPayloadSkipped proves a payload shorter than 8 bytes
// (not even a full discriminator) returns ok=false, err=nil.
func TestDecodeTruncatedPayloadSkipped(t *testing.T) {
	name, data, ok, err := Decode(RoleVault, []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("Decode(short): unexpected error %v", err)
	}
	if ok {
		t.Fatalf("Decode(short): ok=true, want false (name=%q data=%v)", name, data)
	}
}

// TestDecodeTruncatedBodyErrors proves a recognized discriminator whose
// body is too short to hold its declared fields is a genuine decode error
// (not silently skipped), since the discriminator DID match — this is a
// malformed/corrupt log, not an unrelated program's data line.
func TestDecodeTruncatedBodyErrors(t *testing.T) {
	disc := [8]byte{20, 112, 33, 232, 177, 248, 215, 233} // Purchased
	payload := buildPayload(disc, []byte{1, 2, 3})        // far too short for buyer pubkey alone
	_, _, ok, err := Decode(RoleVault, payload)
	if ok {
		t.Fatal("Decode(truncated body): ok=true, want false")
	}
	if err == nil {
		t.Fatal("Decode(truncated body): expected an error")
	}
}
