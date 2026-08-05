package blockchain

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// maxRPCResponseBytes bounds how much of an RPC response body call ever
// reads, regardless of what the server claims/sends — a malicious or
// misbehaving endpoint returning an unbounded body must not be able to
// exhaust memory. Solana RPC responses (a getTransaction result is the
// largest of the 3 calls Indexer makes) are comfortably under this in
// normal operation.
const maxRPCResponseBytes = 16 << 20 // 16 MiB

// SigInfo is one entry from getSignaturesForAddress.
type SigInfo struct {
	Signature string
	Slot      uint64
	// Err is the transaction's on-chain error, if any (RPC field "err"),
	// nil for a successful transaction. Its shape is an opaque
	// TransactionError JSON value; the indexer only checks it for nil-ness.
	Err       any
	BlockTime *int64
}

// TxMeta is the subset of getTransaction's "meta" the indexer needs.
type TxMeta struct {
	// Err mirrors SigInfo.Err: non-nil means the transaction failed
	// on-chain and its logs must not be trusted as having actually run.
	Err         any
	LogMessages []string
}

// Tx is the subset of a getTransaction response the indexer needs.
type Tx struct {
	Slot uint64
	Meta TxMeta
}

// Source is the subset of the Solana JSON-RPC API Indexer needs.
// Satisfied by RPCClient (real node) and fakeSource (tests).
type Source interface {
	GetSlot(ctx context.Context, commitment string) (uint64, error)
	GetSignaturesForAddress(ctx context.Context, program string, limit int, before, until, commitment string) ([]SigInfo, error)
	GetTransaction(ctx context.Context, sig, commitment string) (*Tx, error)
	// GetGenesisHash returns the base58-encoded genesis hash identifying the
	// cluster the RPC endpoint serves — used at startup (see cmd/platform's
	// runPlatform) to cross-check against the configured
	// chain.cluster_genesis, mirroring the EVM path's CheckChainID/
	// ErrWrongChain guard. Not called by Indexer itself, but kept on this
	// interface so every Source implementation (real and fake) stays
	// interface-complete.
	GetGenesisHash(ctx context.Context) (string, error)
}

// RPCClient is a minimal Solana JSON-RPC client over net/http — only the 3
// methods Indexer actually calls, so the package avoids pulling in a
// heavyweight Solana SDK dependency.
type RPCClient struct {
	url        string
	httpClient *http.Client
}

// NewRPCClient constructs an RPCClient targeting url (e.g.
// cfg.RPCURL).
func NewRPCClient(url string) *RPCClient {
	return &RPCClient{url: url, httpClient: &http.Client{Timeout: 30 * time.Second}}
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

// call issues one JSON-RPC request and unmarshals its "result" into out
// (skipped if out is nil).
func (c *RPCClient) call(ctx context.Context, method string, params []any, out any) error {
	reqBody, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	if err != nil {
		return fmt.Errorf("blockchain: marshal %s request: %w", method, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("blockchain: build %s request: %w", method, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("blockchain: rpc %s: %w", method, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxRPCResponseBytes))
		return fmt.Errorf("blockchain: rpc %s: unexpected HTTP status %d: %s", method, resp.StatusCode, body)
	}

	var rr rpcResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRPCResponseBytes)).Decode(&rr); err != nil {
		return fmt.Errorf("blockchain: rpc %s: decode response: %w", method, err)
	}
	if rr.Error != nil {
		return fmt.Errorf("blockchain: rpc %s: %d %s", method, rr.Error.Code, rr.Error.Message)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(rr.Result, out); err != nil {
		return fmt.Errorf("blockchain: rpc %s: unmarshal result: %w", method, err)
	}
	return nil
}

// GetGenesisHash returns the base58-encoded genesis hash of the cluster
// this client's RPC endpoint serves. getGenesisHash takes no parameters —
// unlike GetSlot/GetSignaturesForAddress/GetTransaction, it is not
// commitment-scoped (a cluster's genesis hash is a fixed identity, not
// state that varies by commitment level).
func (c *RPCClient) GetGenesisHash(ctx context.Context) (string, error) {
	var hash string
	if err := c.call(ctx, "getGenesisHash", []any{}, &hash); err != nil {
		return "", err
	}
	return hash, nil
}

// accountInfoWire is the "value" shape getAccountInfo returns with
// encoding "base64": data is a two-element [data, encoding] array, owner is
// the base58-encoded program that owns the account, or the whole value is
// null if the account does not exist.
type accountInfoWire struct {
	Value *struct {
		Data  []string `json:"data"`
		Owner string   `json:"owner"`
	} `json:"value"`
}

// AccountInfo is the subset of getAccountInfo's result GetAccountInfo
// returns: the account's raw data (base64-decoded) and its OWNER program.
// Both are needed by a caller that must confirm an account is genuinely of a
// specific Anchor account type belonging to a specific program — the data
// bytes alone can't rule out an unrelated account of the same length owned
// by some other program entirely (see cmd/platform's
// verifyVaultConfigOnChain).
type AccountInfo struct {
	Data  []byte
	Owner string
}

// GetAccountInfo fetches account's raw data and owner at commitment.
// Returns (nil, nil) — not an error — if the account does not exist yet
// (getAccountInfo's documented "value": null response), so a caller doing a
// best-effort boot-time cross-check (e.g. cmd/platform's
// verifyVaultConfigOnChain) can distinguish "not initialized yet"
// from a genuine RPC failure.
func (c *RPCClient) GetAccountInfo(ctx context.Context, pubkey string, commitment string) (*AccountInfo, error) {
	var wire accountInfoWire
	opts := map[string]any{"encoding": "base64", "commitment": commitment}
	if err := c.call(ctx, "getAccountInfo", []any{pubkey, opts}, &wire); err != nil {
		return nil, err
	}
	if wire.Value == nil || len(wire.Value.Data) == 0 {
		return nil, nil
	}
	data, err := base64.StdEncoding.DecodeString(wire.Value.Data[0])
	if err != nil {
		return nil, fmt.Errorf("blockchain: getAccountInfo %s: decoding base64 data: %w", pubkey, err)
	}
	return &AccountInfo{Data: data, Owner: wire.Value.Owner}, nil
}

// GetSlot returns the current slot at commitment.
func (c *RPCClient) GetSlot(ctx context.Context, commitment string) (uint64, error) {
	var slot uint64
	if err := c.call(ctx, "getSlot", []any{map[string]any{"commitment": commitment}}, &slot); err != nil {
		return 0, err
	}
	return slot, nil
}

type getSignaturesOpts struct {
	Limit      int    `json:"limit,omitempty"`
	Before     string `json:"before,omitempty"`
	Until      string `json:"until,omitempty"`
	Commitment string `json:"commitment,omitempty"`
}

type sigInfoWire struct {
	Signature string `json:"signature"`
	Slot      uint64 `json:"slot"`
	Err       any    `json:"err"`
	BlockTime *int64 `json:"blockTime"`
}

// GetSignaturesForAddress pages confirmed signatures involving program,
// newest-first, matching getSignaturesForAddress's documented semantics:
// before/until bound the returned range exclusively, limit caps the page
// size (max 1000, enforced by the RPC node itself).
func (c *RPCClient) GetSignaturesForAddress(ctx context.Context, program string, limit int, before, until, commitment string) ([]SigInfo, error) {
	var wire []sigInfoWire
	opts := getSignaturesOpts{Limit: limit, Before: before, Until: until, Commitment: commitment}
	if err := c.call(ctx, "getSignaturesForAddress", []any{program, opts}, &wire); err != nil {
		return nil, err
	}
	out := make([]SigInfo, len(wire))
	for i, w := range wire {
		out[i] = SigInfo{Signature: w.Signature, Slot: w.Slot, Err: w.Err, BlockTime: w.BlockTime}
	}
	return out, nil
}

type getTransactionOpts struct {
	Encoding   string `json:"encoding"`
	Commitment string `json:"commitment,omitempty"`
	// MaxSupportedTransactionVersion has no omitempty: 0 must be sent
	// explicitly (it means "accept up to version 0", i.e. legacy +
	// version-0 transactions) — omitting it entirely makes the RPC reject
	// any versioned transaction outright.
	MaxSupportedTransactionVersion int `json:"maxSupportedTransactionVersion"`
}

type txWire struct {
	Slot uint64 `json:"slot"`
	Meta struct {
		Err         any      `json:"err"`
		LogMessages []string `json:"logMessages"`
	} `json:"meta"`
}

// GetTransaction fetches one confirmed transaction by signature.
func (c *RPCClient) GetTransaction(ctx context.Context, sig, commitment string) (*Tx, error) {
	var wire *txWire
	opts := getTransactionOpts{Encoding: "json", Commitment: commitment, MaxSupportedTransactionVersion: 0}
	if err := c.call(ctx, "getTransaction", []any{sig, opts}, &wire); err != nil {
		return nil, err
	}
	if wire == nil {
		return nil, fmt.Errorf("blockchain: getTransaction %s: not found", sig)
	}
	return &Tx{Slot: wire.Slot, Meta: TxMeta{Err: wire.Meta.Err, LogMessages: wire.Meta.LogMessages}}, nil
}

// Submitter is the subset of the Solana JSON-RPC API a transaction-
// broadcasting caller needs (getLatestBlockhash + sendTransaction) — kept
// as its own interface, separate from Source (the indexer's
// read-only subset), so a fake used for compliance-status-write tests
// doesn't have to also implement the indexer's read methods, and vice
// versa. Satisfied by RPCClient (real node) and any test fake.
type Submitter interface {
	GetLatestBlockhash(ctx context.Context, commitment string) (blockhash string, lastValidBlockHeight uint64, err error)
	SendTransaction(ctx context.Context, base64Tx string, opts SendTransactionOpts) (signature string, err error)
}

type getLatestBlockhashOpts struct {
	Commitment string `json:"commitment,omitempty"`
}

type latestBlockhashWire struct {
	Value struct {
		Blockhash            string `json:"blockhash"`
		LastValidBlockHeight uint64 `json:"lastValidBlockHeight"`
	} `json:"value"`
}

// GetLatestBlockhash fetches the recent blockhash a transaction's Message
// must be built against (it expires after ~150 slots — roughly a minute —
// which is what lastValidBlockHeight bounds) and the block height it
// remains valid through.
func (c *RPCClient) GetLatestBlockhash(ctx context.Context, commitment string) (blockhash string, lastValidBlockHeight uint64, err error) {
	var wire latestBlockhashWire
	opts := getLatestBlockhashOpts{Commitment: commitment}
	if err := c.call(ctx, "getLatestBlockhash", []any{opts}, &wire); err != nil {
		return "", 0, err
	}
	return wire.Value.Blockhash, wire.Value.LastValidBlockHeight, nil
}

// SendTransactionOpts mirrors sendTransaction's config object. Encoding is
// always "base64" from this client's side (see SendTransaction) — not
// exposed here since there is only one correct value for how this client
// serializes a transaction.
type SendTransactionOpts struct {
	// SkipPreflight disables the RPC node's own simulate-before-broadcast
	// check. false (the default, zero value) is the safer choice — a
	// simulation failure (e.g. wrong PDA, insufficient funds, the wrong
	// authority signing) is caught here as an RPC error instead of only
	// showing up later as an on-chain revert.
	SkipPreflight bool
	// PreflightCommitment selects which bank state the preflight
	// simulation (if not skipped) runs against. Empty leaves it to the
	// node's own default.
	PreflightCommitment string
	// MaxRetries bounds how many times the RPC node itself rebroadcasts
	// the transaction while waiting for it to land, before giving up. 0
	// leaves it to the node's own default retry policy.
	MaxRetries int
}

type sendTransactionOptsWire struct {
	Encoding            string `json:"encoding"`
	SkipPreflight       bool   `json:"skipPreflight"`
	PreflightCommitment string `json:"preflightCommitment,omitempty"`
	MaxRetries          *int   `json:"maxRetries,omitempty"`
}

// SendTransaction submits a fully signed, base64-encoded wire transaction
// (see tx.go's Sign/Serialize) and returns its signature — which, for a
// transaction with the fee payer as its first required signer, is simply
// the base58 encoding of that signer's own signature over the message; the
// RPC node does not invent it. A successful call means the node accepted
// the transaction for broadcast, NOT that it has landed/confirmed —
// confirmation must be polled separately (e.g. getSignatureStatuses or
// getTransaction), which this minimal client does not yet do — see
// internal/compliance's status service for how it currently
// degrades that gap.
func (c *RPCClient) SendTransaction(ctx context.Context, base64Tx string, opts SendTransactionOpts) (signature string, err error) {
	wireOpts := sendTransactionOptsWire{
		Encoding: "base64", SkipPreflight: opts.SkipPreflight, PreflightCommitment: opts.PreflightCommitment,
	}
	if opts.MaxRetries > 0 {
		wireOpts.MaxRetries = &opts.MaxRetries
	}
	var sig string
	if err := c.call(ctx, "sendTransaction", []any{base64Tx, wireOpts}, &sig); err != nil {
		return "", err
	}
	return sig, nil
}
