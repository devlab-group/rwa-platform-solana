package attestation

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// loadJSON reads and parses the JSON document at path into a T, failing the
// test on any error. Shared by every vector-driven test in this package.
func loadJSON[T any](t *testing.T, path string) T {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return v
}

// mustHash32 decodes a 0x-prefixed 32-byte hex string, failing the test if
// it isn't exactly 32 bytes.
func mustHash32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatalf("decoding hash %q: %v", s, err)
	}
	if len(b) != 32 {
		t.Fatalf("hash %q is %d bytes, want 32", s, len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}
