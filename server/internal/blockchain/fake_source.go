package blockchain

import (
	"context"
	"fmt"
	"sync"
)

// fakeTx is one submitted transaction in a fakeSource's per-program
// history.
type fakeTx struct {
	sig SigInfo
	tx  Tx
}

// fakeSource is an in-memory Source for tests, mirroring the spirit
// of evm/indexer.FakeSource: a flat, ordered per-program transaction
// history, with GetSignaturesForAddress implementing the same
// before/until/limit paging semantics the real getSignaturesForAddress RPC
// documents (results are newest-first; `before` returns only signatures
// older than it; `until` stops before returning it), so Indexer's
// pagination logic can be exercised without a live validator.
type fakeSource struct {
	mu   sync.Mutex
	slot uint64
	// txs holds, per program, every AddTx'd transaction in OLDEST-first
	// insertion order (matching how a test builds up chain history);
	// GetSignaturesForAddress reverses to newest-first when serving results.
	txs map[string][]fakeTx
	// genesisHash/genesisErr back GetGenesisHash — see SetGenesisHash/
	// SetGenesisHashErr.
	genesisHash string
	genesisErr  error
}

func newFakeSource() *fakeSource {
	return &fakeSource{txs: map[string][]fakeTx{}}
}

// SetSlot sets the slot GetSlot reports.
func (f *fakeSource) SetSlot(slot uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.slot = slot
}

// AddTx appends the next (oldest-to-newest) transaction for program.
func (f *fakeSource) AddTx(program string, sig SigInfo, logMessages []string, txErr any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.txs[program] = append(f.txs[program], fakeTx{
		sig: sig,
		tx:  Tx{Slot: sig.Slot, Meta: TxMeta{Err: txErr, LogMessages: logMessages}},
	})
}

func (f *fakeSource) GetSlot(ctx context.Context, commitment string) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.slot, nil
}

// SetGenesisHash sets the value GetGenesisHash reports.
func (f *fakeSource) SetGenesisHash(hash string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.genesisHash = hash
}

// SetGenesisHashErr makes GetGenesisHash fail with err (a nil resets it to
// succeed again).
func (f *fakeSource) SetGenesisHashErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.genesisErr = err
}

func (f *fakeSource) GetGenesisHash(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.genesisErr != nil {
		return "", f.genesisErr
	}
	return f.genesisHash, nil
}

func (f *fakeSource) GetSignaturesForAddress(ctx context.Context, program string, limit int, before, until, commitment string) ([]SigInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	stored := f.txs[program]
	newestFirst := make([]fakeTx, len(stored))
	for i, t := range stored {
		newestFirst[len(stored)-1-i] = t
	}

	start := 0
	if before != "" {
		i := indexOfSig(newestFirst, before)
		if i < 0 {
			return nil, fmt.Errorf("fakeSource: before signature %q not found", before)
		}
		start = i + 1
	}

	out := make([]SigInfo, 0, limit)
	for i := start; i < len(newestFirst); i++ {
		if until != "" && newestFirst[i].sig.Signature == until {
			break
		}
		out = append(out, newestFirst[i].sig)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func indexOfSig(list []fakeTx, sig string) int {
	for i, t := range list {
		if t.sig.Signature == sig {
			return i
		}
	}
	return -1
}

func (f *fakeSource) GetTransaction(ctx context.Context, sig, commitment string) (*Tx, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, txs := range f.txs {
		for _, t := range txs {
			if t.sig.Signature == sig {
				cp := t.tx
				cp.Meta.LogMessages = append([]string(nil), t.tx.Meta.LogMessages...)
				return &cp, nil
			}
		}
	}
	return nil, fmt.Errorf("fakeSource: transaction %q not found", sig)
}
