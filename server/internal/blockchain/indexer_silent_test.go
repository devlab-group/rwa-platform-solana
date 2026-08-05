package blockchain

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/rwa-platform/server/internal/dal/memory"
)

// silentSource is an RPC whose address index has been pruned: every call
// succeeds and returns an empty page. This is the shape that made a real
// incident invisible — an error would have been logged, an empty array is not.
type silentSource struct{}

func (silentSource) GetSlot(context.Context, string) (uint64, error) { return 1000, nil }
func (silentSource) GetSignaturesForAddress(context.Context, string, int, string, string, string) ([]SigInfo, error) {
	return nil, nil
}
func (silentSource) GetTransaction(context.Context, string, string) (*Tx, error) { return nil, nil }
func (silentSource) GetGenesisHash(context.Context) (string, error)              { return "", nil }

// TestIndexerWarnsWhenPollingSilently: after the grace period, a program that
// polls successfully but has never indexed anything must say so. Without this
// the only symptom is empty read models and no log output at all.
func TestIndexerWarnsWhenPollingSilently(t *testing.T) {
	repos := memory.New()
	const programID = "VauLT1111111111111111111111111111111111111"
	idx := New(silentSource{}, repos.IndexerCheckpoints, repos.ChainEvents,
		map[ProgramRole]string{RoleVault: programID}, 900001, "finalized", 0)

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(nil)

	ctx := context.Background()
	if err := idx.Poll(ctx); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if strings.Contains(buf.String(), "NO signatures") {
		t.Fatal("must not warn on the very first quiet poll — a fresh deployment is legitimately in this state")
	}

	// Backdate the first-seen marker past the grace period rather than
	// sleeping two minutes.
	idx.silentSince[programID] = time.Now().Add(-silentPollWarnAfter - time.Minute)
	if err := idx.Poll(ctx); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "NO signatures") {
		t.Errorf("expected a warning after the grace period, got: %q", out)
	}
	if !strings.Contains(out, "opsctl indexer probe") {
		t.Error("the warning should point at the tool that diagnoses it")
	}
}

// TestIndexerSilentWarningIsRateLimited: the warning must be a standing
// signal, not 5s log spam.
func TestIndexerSilentWarningIsRateLimited(t *testing.T) {
	repos := memory.New()
	const programID = "VauLT1111111111111111111111111111111111111"
	idx := New(silentSource{}, repos.IndexerCheckpoints, repos.ChainEvents,
		map[ProgramRole]string{RoleVault: programID}, 900001, "finalized", 0)

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(nil)

	ctx := context.Background()
	_ = idx.Poll(ctx)
	idx.silentSince[programID] = time.Now().Add(-silentPollWarnAfter - time.Minute)
	for i := 0; i < 5; i++ {
		_ = idx.Poll(ctx)
	}
	if n := strings.Count(buf.String(), "NO signatures"); n != 1 {
		t.Errorf("warned %d times across 5 polls, want exactly 1", n)
	}
}
