package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rwa-platform/signer/internal/base58"
)

func testKey(b byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = b
	}
	return base58.Encode(raw)
}

func validPolicy() map[string]any {
	return map[string]any{
		"cluster":       testKey(0x11),
		"program":       testKey(0x22),
		"config":        testKey(0x33),
		"vault":         testKey(0x77),
		"auditor":       "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		"projectId":     "4fd4224f-6e65-4d6b-9fa9-c5c2b3514e61",
		"profileDigest": "0x1111111111111111111111111111111111111111111111111111111111111111",
	}
}

func writePolicy(t *testing.T, m map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshaling policy: %v", err)
	}
	path := filepath.Join(t.TempDir(), "solana-policy.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("writing policy: %v", err)
	}
	return path
}

func TestLoad_Valid(t *testing.T) {
	p, err := Load(writePolicy(t, validPolicy()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// The decoded byte form must be derived from the same string the review
	// screen shows, so the two can never disagree.
	want, err := base58.DecodePubkey(testKey(0x22))
	if err != nil {
		t.Fatalf("DecodePubkey: %v", err)
	}
	if p.ProgramBytes != want {
		t.Errorf("ProgramBytes = %x, want %x", p.ProgramBytes, want)
	}
	if p.MaxAttestationLifetime != DefaultMaxAttestationLifetime {
		t.Errorf("MaxAttestationLifetime = %s, want the default %s", p.MaxAttestationLifetime, DefaultMaxAttestationLifetime)
	}
}

func TestLoad_HonorsMaxLifetimeOverride(t *testing.T) {
	m := validPolicy()
	m["maxAttestationLifetimeHours"] = 48
	p, err := Load(writePolicy(t, m))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.MaxAttestationLifetime != 48*time.Hour {
		t.Fatalf("MaxAttestationLifetime = %s, want 48h", p.MaxAttestationLifetime)
	}
}

// TestLoad_RejectsIncomplete: there is no default trust root. Every
// field missing from the policy would otherwise become a field the package
// gets to decide for itself.
func TestLoad_RejectsIncomplete(t *testing.T) {
	for _, field := range []string{"cluster", "program", "config", "vault", "auditor", "projectId", "profileDigest"} {
		t.Run("missing "+field, func(t *testing.T) {
			m := validPolicy()
			delete(m, field)
			if _, err := Load(writePolicy(t, m)); err == nil {
				t.Fatalf("accepted a policy with no %s", field)
			}
		})
	}
}

func TestLoad_RejectsMalformedFields(t *testing.T) {
	cases := map[string]map[string]any{
		"non-base58 program":      {"program": "not!base58"},
		"wrong-length cluster":    {"cluster": base58.Encode([]byte{1, 2, 3})},
		"EVM-style hex vault":     {"vault": "0x7777777777777777777777777777777777777777777777777777777777777777"},
		"auditor not an address":  {"auditor": "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"},
		"profileDigest too short": {"profileDigest": "0x1111"},
		"negative max lifetime":   {"maxAttestationLifetimeHours": -1},
	}
	for name, patch := range cases {
		t.Run(name, func(t *testing.T) {
			m := validPolicy()
			for k, v := range patch {
				m[k] = v
			}
			if _, err := Load(writePolicy(t, m)); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}

// TestLoad_RejectsForeignPolicyShape guards the policy loader against
// a document shaped for some other trust root entirely -- one that carries
// a chain-id/controller pair instead of the required cluster/program/config
// triple. Such a file must not be silently accepted with cluster, program
// and config left unpinned.
func TestLoad_RejectsForeignPolicyShape(t *testing.T) {
	foreign := map[string]any{
		"chainId":       "31337",
		"controller":    "0x5FbDB2315678afecb367f032d93F642f64180aa3",
		"vault":         "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
		"auditor":       "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		"projectId":     "4fd4224f-6e65-4d6b-9fa9-c5c2b3514e61",
		"profileDigest": "0x1111111111111111111111111111111111111111111111111111111111111111",
	}
	if _, err := Load(writePolicy(t, foreign)); err == nil {
		t.Fatal("Load accepted a foreign-shaped policy file")
	}
}
