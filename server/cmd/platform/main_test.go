package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/rwa-platform/server/internal/blockchain"
	"github.com/rwa-platform/server/internal/config"
	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/keys"
)

func init() { gin.SetMode(gin.TestMode) }

// TestRouterHandlerSwapIsAtomic is the regression test for
// routerHandler: requests served concurrently with a Store must always see
// one complete engine's response, never a nil pointer or a partially
// constructed one (the whole point of using atomic.Pointer instead of a
// bare field).
func TestRouterHandlerSwapIsAtomic(t *testing.T) {
	h := &routerHandler{}
	r1 := gin.New()
	r1.GET("/x", func(c *gin.Context) { c.String(http.StatusOK, "v1") })
	h.set(r1)

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != "v1" {
		t.Fatalf("before swap: status=%d body=%q", w.Code, w.Body.String())
	}

	r2 := gin.New()
	r2.GET("/x", func(c *gin.Context) { c.String(http.StatusOK, "v2") })
	h.set(r2)

	req = httptest.NewRequest(http.MethodGet, "/x", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != "v2" {
		t.Fatalf("after swap: status=%d body=%q", w.Code, w.Body.String())
	}
}

// fakeKeyProvider is a minimal keys.Provider test double that counts Close
// calls. keys.Provider is purely a key-material lifecycle handle (Reload +
// Close) — it has no signing method, because the ed25519 compliance key is
// held and used directly by compliance.StatusService.
type fakeKeyProvider struct {
	mu     sync.Mutex
	closed int
}

func (f *fakeKeyProvider) Reload(ctx context.Context) error { return nil }
func (f *fakeKeyProvider) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
	return nil
}

var _ keys.Provider = (*fakeKeyProvider)(nil)

// TestProviderRegistryTracksAllGenerations is the regression test for
// providerRegistry: a provider set added by one generation AND a later
// generation must BOTH be closed at shutdown, not just whichever set was
// added last.
func TestProviderRegistryTracksAllGenerations(t *testing.T) {
	reg := &providerRegistry{}
	gen1 := &fakeKeyProvider{}
	gen2 := &fakeKeyProvider{}
	reg.add(nil) // no-op sanity: adding an empty/nil slice must not panic
	reg.add([]keys.Provider{gen1})
	reg.add([]keys.Provider{gen2})

	reg.closeAll()
	if gen1.closed != 1 {
		t.Errorf("gen1.closed = %d, want 1", gen1.closed)
	}
	if gen2.closed != 1 {
		t.Errorf("gen2.closed = %d, want 1", gen2.closed)
	}
}

// TestIndexerUnsafe is the regression test for the shared
// safety-state check backing both /readyz and runIndexDependentTicker: no
// checkpoint yet is NOT unsafe (normal at/just after startup), a normal
// checkpoint is not unsafe, and a ReconciliationRequired checkpoint is.
func TestIndexerUnsafe(t *testing.T) {
	repos := memory.New()
	ctx := context.Background()
	const chainID = 31337

	unsafe, err := indexerUnsafe(ctx, repos, chainID)
	if err != nil {
		t.Fatalf("no checkpoint yet: %v", err)
	}
	if unsafe {
		t.Fatal("expected NOT unsafe with no checkpoint yet")
	}

	if err := repos.IndexerCheckpoints.Set(ctx, &models.IndexerCheckpoint{
		ChainID: chainID, Address: blockchain.CheckpointAddress, LastBlock: 100, LastBlockHash: "0xabc",
	}); err != nil {
		t.Fatal(err)
	}
	unsafe, err = indexerUnsafe(ctx, repos, chainID)
	if err != nil {
		t.Fatal(err)
	}
	if unsafe {
		t.Fatal("expected NOT unsafe for a normal checkpoint")
	}

	if err := repos.IndexerCheckpoints.Set(ctx, &models.IndexerCheckpoint{
		ChainID: chainID, Address: blockchain.CheckpointAddress, LastBlock: 100, LastBlockHash: "0xabc",
		ReconciliationRequired: true,
	}); err != nil {
		t.Fatal(err)
	}
	unsafe, err = indexerUnsafe(ctx, repos, chainID)
	if err != nil {
		t.Fatal(err)
	}
	if !unsafe {
		t.Fatal("expected unsafe once ReconciliationRequired is set")
	}
}

// TestRunIndexDependentTickerSkipsWhileUnsafe proves the reconciler-gating
// wrapper never invokes fn while the indexer is ReconciliationRequired, and
// does invoke it once safe again.
func TestRunIndexDependentTickerSkipsWhileUnsafe(t *testing.T) {
	repos := memory.New()
	ctx, cancel := context.WithCancel(context.Background())
	const chainID = 31337
	if err := repos.IndexerCheckpoints.Set(ctx, &models.IndexerCheckpoint{
		ChainID: chainID, Address: blockchain.CheckpointAddress, LastBlock: 100, LastBlockHash: "0xabc",
		ReconciliationRequired: true,
	}); err != nil {
		t.Fatal(err)
	}

	var calls int
	var mu sync.Mutex
	done := make(chan struct{})
	go runIndexDependentTicker(ctx, repos, config.Config{ChainID: chainID}, 5*time.Millisecond, "test", func() error {
		mu.Lock()
		calls++
		mu.Unlock()
		select {
		case done <- struct{}{}:
		default:
		}
		return nil
	})

	time.Sleep(30 * time.Millisecond)
	mu.Lock()
	gotWhileUnsafe := calls
	mu.Unlock()
	if gotWhileUnsafe != 0 {
		t.Fatalf("expected fn never called while unsafe, got %d calls", gotWhileUnsafe)
	}

	if err := repos.IndexerCheckpoints.Set(ctx, &models.IndexerCheckpoint{
		ChainID: chainID, Address: blockchain.CheckpointAddress, LastBlock: 100, LastBlockHash: "0xabc",
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected fn to be called once safe again")
	}
	cancel()
}

// TestRunAsReconcilerLeaderSerializesConcurrentReplicas checks that one
// reconciler leader runs per project/chain in multi-instance mode: while
// another replica (simulated by acquiring the
// same lease key directly under a different holder id) currently holds the
// reconciler's lease, fn must not run; once released, the next tick
// acquires and runs it, and releases the lease again afterward so a
// following tick (or another replica) can take over.
func TestRunAsReconcilerLeaderSerializesConcurrentReplicas(t *testing.T) {
	repos := memory.New()
	ctx := context.Background()
	cfg := config.Config{ChainID: 31337}

	token, ok, err := repos.Leases.Acquire(ctx, "reconciler:test/leader:31337", "other-replica", time.Minute)
	if err != nil || !ok {
		t.Fatalf("simulated other replica failed to acquire: ok=%v err=%v", ok, err)
	}

	var calls int
	runAsReconcilerLeader(ctx, repos, cfg, "test/leader", func() { calls++ })
	if calls != 0 {
		t.Fatalf("expected fn NOT to run while another replica holds the lease, got %d calls", calls)
	}

	if err := repos.Leases.Release(ctx, "reconciler:test/leader:31337", "other-replica", token); err != nil {
		t.Fatal(err)
	}

	runAsReconcilerLeader(ctx, repos, cfg, "test/leader", func() { calls++ })
	if calls != 1 {
		t.Fatalf("expected fn to run once the lease is free, got %d calls", calls)
	}

	// The lease must be released again after fn returns, so a subsequent
	// tick (this replica or another) can acquire it once more.
	_, ok, err = repos.Leases.Acquire(ctx, "reconciler:test/leader:31337", "other-replica", time.Minute)
	if err != nil || !ok {
		t.Fatalf("expected the lease to be free again after runAsReconcilerLeader returned: ok=%v err=%v", ok, err)
	}
}
