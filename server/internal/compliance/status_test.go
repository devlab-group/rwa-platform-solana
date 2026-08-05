package compliance

import "testing"

func TestStatusFromString(t *testing.T) {
	cases := map[string]OnChainStatus{"Unknown": OnChainStatusUnknown, "Allowed": OnChainStatusAllowed, "Blocked": OnChainStatusBlocked}
	for s, want := range cases {
		got, ok := StatusFromString(s)
		if !ok || got != want {
			t.Errorf("StatusFromString(%q) = %v,%v want %v,true", s, got, ok, want)
		}
	}
	if _, ok := StatusFromString("bogus"); ok {
		t.Error("expected ok=false for unknown status string")
	}
}
