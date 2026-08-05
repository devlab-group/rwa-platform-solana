package blockchain

import (
	"reflect"
	"testing"
)

// pauseSetDisc is the real Compliance IDL discriminator for PauseSet, the
// only event among the 5 embedded IDLs with a bool field (paused) — see
// idl/rwa_compliance.json.
var pauseSetDisc = [8]byte{175, 57, 198, 136, 192, 66, 204, 73}

// TestDecodePauseSet is the only end-to-end (Decode-level) coverage of
// KindBool: it proves a true/false byte decodes to an actual Go bool in
// ChainEvent.Data, not a string or a uint like the numeric kinds.
func TestDecodePauseSet(t *testing.T) {
	byRaw, byB58 := pubkeyBytes(0x0C)

	for _, paused := range []bool{true, false} {
		pausedByte := byte(0)
		if paused {
			pausedByte = 1
		}
		payload := buildPayload(pauseSetDisc, []byte{pausedByte}, byRaw)

		name, data, ok, err := Decode(RoleCompliance, payload)
		if err != nil || !ok {
			t.Fatalf("Decode(paused=%v): ok=%v err=%v", paused, ok, err)
		}
		if name != "PauseSet" {
			t.Errorf("name = %q, want PauseSet", name)
		}
		want := map[string]any{"paused": paused, "by": byB58}
		if !reflect.DeepEqual(data, want) {
			t.Errorf("data = %#v, want %#v", data, want)
		}
		gotPaused, ok := data["paused"].(bool)
		if !ok {
			t.Fatalf("data[\"paused\"] has Go type %T, want bool", data["paused"])
		}
		if gotPaused != paused {
			t.Errorf("data[\"paused\"] = %v, want %v", gotPaused, paused)
		}
	}
}

// TestDecodePauseSet_InvalidBoolByte proves a bool field whose wire byte is
// neither 0 nor 1 is a hard decode error (ok=false, err!=nil) — the
// discriminator matched, so this is corrupt data, not an unrelated
// program's log line to skip silently.
func TestDecodePauseSet_InvalidBoolByte(t *testing.T) {
	byRaw, _ := pubkeyBytes(0x0C)
	payload := buildPayload(pauseSetDisc, []byte{0x02}, byRaw)

	_, _, ok, err := Decode(RoleCompliance, payload)
	if ok {
		t.Fatal("Decode(invalid bool byte): ok=true, want false")
	}
	if err == nil {
		t.Fatal("Decode(invalid bool byte): expected an error")
	}
}

// TestDecodeUnknownProgramRole proves Decode rejects a ProgramRole with no
// registered IDL (a value outside {RoleCompliance..RoleSupplyController}) as
// a hard error, distinct from an unrecognized discriminator: an unknown role
// means the caller itself is misconfigured, which must not be swallowed the
// same way a garbage log line is.
func TestDecodeUnknownProgramRole(t *testing.T) {
	unknown := ProgramRole(99)
	_, _, ok, err := Decode(unknown, buildPayload(purchasedDisc, []byte{1, 2, 3, 4}))
	if ok {
		t.Fatal("Decode(unknown role): ok=true, want false")
	}
	if err == nil {
		t.Fatal("Decode(unknown role): expected an error naming the unknown role")
	}
}

// TestBorshReaderU64String_GoTypeAndValue pins u64String's Go return type
// (string, not uint64) and its decimal rendering — the convention Decode
// relies on for every KindU64 field (e.g. Purchased.tokenAmount,
// RedemptionRequested.createdAt).
func TestBorshReaderU64String_GoTypeAndValue(t *testing.T) {
	r := newBorshReader(leU64(18446744073709551615)) // math.MaxUint64
	v, err := r.u64String()
	if err != nil {
		t.Fatalf("u64String: %v", err)
	}
	if reflect.TypeOf(v).Kind() != reflect.String {
		t.Fatalf("u64String returned Go type %T, want string", v)
	}
	if v != "18446744073709551615" {
		t.Errorf("u64String = %q, want 18446744073709551615", v)
	}
}

// TestBorshReaderI64String_GoTypeAndValue is u64String's signed counterpart.
// No event in any of the 5 embedded IDLs currently declares an i64 field
// (idl.go's KindI64 case exists for schema completeness with none of today's
// events exercising it via Decode), so this tests borshReader.i64String
// directly — the same decode primitive Decode's KindI64 case calls — proving
// both that a negative value round-trips through the little-endian two's
// complement encoding and that its Go type is string like the unsigned case,
// not int64.
func TestBorshReaderI64String_GoTypeAndValue(t *testing.T) {
	cases := []struct {
		name string
		le   []byte
		want string
	}{
		{"positive", leU64(12345), "12345"},
		{"zero", leU64(0), "0"},
		// -1 as two's complement u64 is 0xFFFFFFFFFFFFFFFF.
		{"minus one", leU64(0xFFFFFFFFFFFFFFFF), "-1"},
		// math.MinInt64 as two's complement u64 is 0x8000000000000000.
		{"min int64", leU64(0x8000000000000000), "-9223372036854775808"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newBorshReader(c.le)
			v, err := r.i64String()
			if err != nil {
				t.Fatalf("i64String: %v", err)
			}
			if reflect.TypeOf(v).Kind() != reflect.String {
				t.Fatalf("i64String returned Go type %T, want string", v)
			}
			if v != c.want {
				t.Errorf("i64String = %q, want %q", v, c.want)
			}
		})
	}
}

// TestBorshReaderU64String_Truncated proves a buffer shorter than 8 bytes is
// a decode error, not a silently zero-padded value.
func TestBorshReaderU64String_Truncated(t *testing.T) {
	r := newBorshReader([]byte{1, 2, 3})
	if _, err := r.u64String(); err == nil {
		t.Fatal("u64String(3 bytes): expected an error")
	}
}
