package blockchain

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Interface-conformance: both the real client and the test fake must
// satisfy the full Source interface, including GetGenesisHash — a
// compile-time check that neither ever silently drifts out of sync with
// the interface.
var (
	_ Source = (*RPCClient)(nil)
	_ Source = (*fakeSource)(nil)
)

// decodeRPCRequest parses one JSON-RPC request body into its method name and
// params, generically (map[string]any/[]any, the same shape encoding/json
// produces for arbitrary JSON), so a test can assert the exact wire shape
// RPCClient.call sends without depending on its unexported request types.
//
// This runs inside the httptest.Server's handler goroutine, not the test's
// own goroutine, so it must only use t.Errorf (safe from any goroutine per
// the testing package's own doc comment) — never t.Fatal/FailNow, which the
// testing package requires be called from the goroutine running the Test
// function.
func decodeRPCRequest(t *testing.T, r *http.Request) (method string, params []any) {
	t.Helper()
	var body struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Method  string `json:"method"`
		Params  []any  `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Errorf("decoding request body: %v", err)
		return "", nil
	}
	if body.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %q, want 2.0", body.JSONRPC)
	}
	return body.Method, body.Params
}

// rpcServer starts an httptest.Server that decodes the one request it
// expects, runs check against its method/params (nil check skips this), and
// replies with resultJSON as the RPC "result" verbatim (so callers control
// the exact response shape, including "null").
func rpcServer(t *testing.T, check func(t *testing.T, method string, params []any), resultJSON string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, params := decodeRPCRequest(t, r)
		if check != nil {
			check(t, method, params)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":%s}`, resultJSON)
	}))
}

// rpcErrorServer replies to any request with a JSON-RPC error object, the
// shape every RPCClient method must surface as a Go error containing code
// and message.
func rpcErrorServer(t *testing.T, code int, message string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		errJSON, err := json.Marshal(message)
		if err != nil {
			// json.Marshal of a plain string cannot fail; this only guards
			// against t.Errorf being unreachable if it somehow did.
			t.Errorf("marshaling error message: %v", err)
			return
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"error":{"code":%d,"message":%s}}`, code, errJSON)
	}))
}

func objParam(t *testing.T, params []any, i int) map[string]any {
	t.Helper()
	if i >= len(params) {
		t.Errorf("params has %d elements, want at least %d", len(params), i+1)
		return nil
	}
	obj, ok := params[i].(map[string]any)
	if !ok {
		t.Errorf("params[%d] = %#v, want a JSON object", i, params[i])
		return nil
	}
	return obj
}

func strParam(t *testing.T, params []any, i int) string {
	t.Helper()
	if i >= len(params) {
		t.Errorf("params has %d elements, want at least %d", len(params), i+1)
		return ""
	}
	s, ok := params[i].(string)
	if !ok {
		t.Errorf("params[%d] = %#v, want a string", i, params[i])
		return ""
	}
	return s
}

// --- GetSlot ---

func TestRPCClient_GetSlot(t *testing.T) {
	srv := rpcServer(t, func(t *testing.T, method string, params []any) {
		if method != "getSlot" {
			t.Errorf("method = %q, want getSlot", method)
		}
		if len(params) != 1 {
			t.Errorf("params = %v, want 1 element", params)
		}
		opts := objParam(t, params, 0)
		if got := opts["commitment"]; got != "finalized" {
			t.Errorf("commitment = %v, want finalized", got)
		}
		if len(opts) != 1 {
			t.Errorf("params[0] has unexpected keys: %v", opts)
		}
	}, `999888777`)
	defer srv.Close()

	c := NewRPCClient(srv.URL)
	slot, err := c.GetSlot(context.Background(), "finalized")
	if err != nil {
		t.Fatalf("GetSlot: %v", err)
	}
	if slot != 999888777 {
		t.Errorf("slot = %d, want 999888777", slot)
	}
}

func TestRPCClient_GetSlot_Error(t *testing.T) {
	srv := rpcErrorServer(t, -32000, "node is behind")
	defer srv.Close()

	c := NewRPCClient(srv.URL)
	_, err := c.GetSlot(context.Background(), "finalized")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "node is behind") {
		t.Errorf("error = %v, want it to mention the RPC error message", err)
	}
}

// --- GetGenesisHash ---

func TestRPCClient_GetGenesisHash(t *testing.T) {
	srv := rpcServer(t, func(t *testing.T, method string, params []any) {
		if method != "getGenesisHash" {
			t.Errorf("method = %q, want getGenesisHash", method)
		}
		if len(params) != 0 {
			t.Errorf("params = %v, want none (getGenesisHash takes no parameters)", params)
		}
	}, `"5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"`)
	defer srv.Close()

	c := NewRPCClient(srv.URL)
	hash, err := c.GetGenesisHash(context.Background())
	if err != nil {
		t.Fatalf("GetGenesisHash: %v", err)
	}
	if hash != "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d" {
		t.Errorf("hash = %q", hash)
	}
}

func TestRPCClient_GetGenesisHash_Error(t *testing.T) {
	srv := rpcErrorServer(t, -32000, "node is unhealthy")
	defer srv.Close()

	c := NewRPCClient(srv.URL)
	_, err := c.GetGenesisHash(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "node is unhealthy") {
		t.Errorf("error = %v", err)
	}
}

// --- GetAccountInfo ---

// TestRPCClient_GetAccountInfo covers the happy path: a base64-encoded
// "data" tuple decodes back to the exact original bytes, used by
// cmd/platform's verifyVaultConfigOnChain to read the
// rwa-supply-controller Config account.
func TestRPCClient_GetAccountInfo(t *testing.T) {
	want := bytes.Repeat([]byte{0xAB}, 156)
	encoded := base64.StdEncoding.EncodeToString(want)
	srv := rpcServer(t, func(t *testing.T, method string, params []any) {
		if method != "getAccountInfo" {
			t.Errorf("method = %q, want getAccountInfo", method)
		}
		if got := strParam(t, params, 0); got != "SomePubkey11111111111111111111111111111111" {
			t.Errorf("params[0] = %q", got)
		}
		opts := objParam(t, params, 1)
		if opts["encoding"] != "base64" {
			t.Errorf("encoding = %v, want base64", opts["encoding"])
		}
		if opts["commitment"] != "finalized" {
			t.Errorf("commitment = %v, want finalized", opts["commitment"])
		}
	}, fmt.Sprintf(`{"value":{"data":[%q,"base64"],"owner":"OwnerProgram1111111111111111111111111111"}}`, encoded))
	defer srv.Close()

	c := NewRPCClient(srv.URL)
	got, err := c.GetAccountInfo(context.Background(), "SomePubkey11111111111111111111111111111111", "finalized")
	if err != nil {
		t.Fatalf("GetAccountInfo: %v", err)
	}
	if !bytes.Equal(got.Data, want) {
		t.Errorf("GetAccountInfo().Data = %x, want %x", got.Data, want)
	}
	if got.Owner != "OwnerProgram1111111111111111111111111111" {
		t.Errorf("GetAccountInfo().Owner = %q, want %q", got.Owner, "OwnerProgram1111111111111111111111111111")
	}
}

// TestRPCClient_GetAccountInfo_NullResult covers the documented "account
// does not exist" response (`"value":null`) — must return (nil, nil), not
// an error, so a caller can distinguish "not initialized yet" from a
// genuine RPC failure.
func TestRPCClient_GetAccountInfo_NullResult(t *testing.T) {
	srv := rpcServer(t, nil, `{"value":null}`)
	defer srv.Close()

	c := NewRPCClient(srv.URL)
	got, err := c.GetAccountInfo(context.Background(), "SomePubkey11111111111111111111111111111111", "finalized")
	if err != nil {
		t.Fatalf("GetAccountInfo: %v", err)
	}
	if got != nil {
		t.Errorf("GetAccountInfo() = %x, want nil for a nonexistent account", got)
	}
}

func TestRPCClient_GetAccountInfo_Error(t *testing.T) {
	srv := rpcErrorServer(t, -32000, "account fetch failed")
	defer srv.Close()

	c := NewRPCClient(srv.URL)
	if _, err := c.GetAccountInfo(context.Background(), "x", "finalized"); err == nil {
		t.Fatal("expected an error")
	} else if !strings.Contains(err.Error(), "account fetch failed") {
		t.Errorf("error = %v", err)
	}
}

// --- call: HTTP status handling ---

// TestRPCClient_NonSuccessHTTPStatusIsAnError proves call surfaces a
// non-2xx HTTP status as a Go error instead of trying to parse a body that
// may not even be JSON-RPC shaped.
func TestRPCClient_NonSuccessHTTPStatusIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, "upstream RPC overloaded")
	}))
	defer srv.Close()

	c := NewRPCClient(srv.URL)
	_, err := c.GetSlot(context.Background(), "finalized")
	if err == nil {
		t.Fatal("expected an error for a 503 response")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error = %v, want it to mention the HTTP status", err)
	}
}

// --- GetSignaturesForAddress ---

func TestRPCClient_GetSignaturesForAddress(t *testing.T) {
	srv := rpcServer(t, func(t *testing.T, method string, params []any) {
		if method != "getSignaturesForAddress" {
			t.Errorf("method = %q, want getSignaturesForAddress", method)
		}
		if got := strParam(t, params, 0); got != vaultProgramID {
			t.Errorf("params[0] = %q, want %q", got, vaultProgramID)
		}
		opts := objParam(t, params, 1)
		if opts["limit"] != float64(1000) {
			t.Errorf("limit = %v, want 1000", opts["limit"])
		}
		if opts["before"] != "sigBefore" {
			t.Errorf("before = %v, want sigBefore", opts["before"])
		}
		if opts["until"] != "sigUntil" {
			t.Errorf("until = %v, want sigUntil", opts["until"])
		}
		if opts["commitment"] != "finalized" {
			t.Errorf("commitment = %v, want finalized", opts["commitment"])
		}
	}, `[
		{"signature":"sig1","slot":5,"err":null,"blockTime":1700000000},
		{"signature":"sig2","slot":6,"err":{"InstructionError":[0,"Custom"]},"blockTime":null}
	]`)
	defer srv.Close()

	c := NewRPCClient(srv.URL)
	sigs, err := c.GetSignaturesForAddress(context.Background(), vaultProgramID, 1000, "sigBefore", "sigUntil", "finalized")
	if err != nil {
		t.Fatalf("GetSignaturesForAddress: %v", err)
	}
	if len(sigs) != 2 {
		t.Fatalf("len(sigs) = %d, want 2", len(sigs))
	}
	if sigs[0].Signature != "sig1" || sigs[0].Slot != 5 || sigs[0].Err != nil {
		t.Errorf("sigs[0] = %+v", sigs[0])
	}
	if sigs[0].BlockTime == nil || *sigs[0].BlockTime != 1700000000 {
		t.Errorf("sigs[0].BlockTime = %v, want 1700000000", sigs[0].BlockTime)
	}
	if sigs[1].Signature != "sig2" || sigs[1].Err == nil {
		t.Errorf("sigs[1] = %+v, want a non-nil Err", sigs[1])
	}
	if sigs[1].BlockTime != nil {
		t.Errorf("sigs[1].BlockTime = %v, want nil", sigs[1].BlockTime)
	}
}

// TestRPCClient_GetSignaturesForAddress_OmitsEmptyBeforeUntil proves before
// and until are left out of the request entirely when empty (omitempty),
// rather than sent as `""` — a real RPC node treats an empty string
// differently from an absent field for these two params.
func TestRPCClient_GetSignaturesForAddress_OmitsEmptyBeforeUntil(t *testing.T) {
	srv := rpcServer(t, func(t *testing.T, method string, params []any) {
		opts := objParam(t, params, 1)
		if _, present := opts["before"]; present {
			t.Errorf("before present when empty: %v", opts["before"])
		}
		if _, present := opts["until"]; present {
			t.Errorf("until present when empty: %v", opts["until"])
		}
	}, `[]`)
	defer srv.Close()

	c := NewRPCClient(srv.URL)
	if _, err := c.GetSignaturesForAddress(context.Background(), vaultProgramID, 1000, "", "", "finalized"); err != nil {
		t.Fatalf("GetSignaturesForAddress: %v", err)
	}
}

// TestRPCClient_GetSignaturesForAddress_NullResult proves a `"result":null`
// response (an RPC node can return this for an address with no history)
// parses to an empty slice, not an error.
func TestRPCClient_GetSignaturesForAddress_NullResult(t *testing.T) {
	srv := rpcServer(t, nil, `null`)
	defer srv.Close()

	c := NewRPCClient(srv.URL)
	sigs, err := c.GetSignaturesForAddress(context.Background(), vaultProgramID, 1000, "", "", "finalized")
	if err != nil {
		t.Fatalf("GetSignaturesForAddress: %v", err)
	}
	if len(sigs) != 0 {
		t.Errorf("sigs = %v, want empty", sigs)
	}
}

func TestRPCClient_GetSignaturesForAddress_Error(t *testing.T) {
	srv := rpcErrorServer(t, -32602, "invalid params")
	defer srv.Close()

	c := NewRPCClient(srv.URL)
	_, err := c.GetSignaturesForAddress(context.Background(), vaultProgramID, 1000, "", "", "finalized")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "invalid params") {
		t.Errorf("error = %v", err)
	}
}

// --- GetTransaction ---

func TestRPCClient_GetTransaction(t *testing.T) {
	srv := rpcServer(t, func(t *testing.T, method string, params []any) {
		if method != "getTransaction" {
			t.Errorf("method = %q, want getTransaction", method)
		}
		if got := strParam(t, params, 0); got != "sig-xyz" {
			t.Errorf("params[0] = %q, want sig-xyz", got)
		}
		opts := objParam(t, params, 1)
		if opts["encoding"] != "json" {
			t.Errorf("encoding = %v, want json", opts["encoding"])
		}
		if opts["commitment"] != "confirmed" {
			t.Errorf("commitment = %v, want confirmed", opts["commitment"])
		}
		// maxSupportedTransactionVersion has no `omitempty`: it must be sent
		// explicitly even at its zero value, or the RPC node rejects any
		// versioned transaction outright — see client.go's doc comment.
		got, present := opts["maxSupportedTransactionVersion"]
		if !present {
			t.Error("maxSupportedTransactionVersion is missing from the request")
		} else if got != float64(0) {
			t.Errorf("maxSupportedTransactionVersion = %v, want 0", got)
		}
	}, `{"slot":42,"meta":{"err":null,"logMessages":["Program log: hi"]}}`)
	defer srv.Close()

	c := NewRPCClient(srv.URL)
	tx, err := c.GetTransaction(context.Background(), "sig-xyz", "confirmed")
	if err != nil {
		t.Fatalf("GetTransaction: %v", err)
	}
	if tx.Slot != 42 {
		t.Errorf("tx.Slot = %d, want 42", tx.Slot)
	}
	if tx.Meta.Err != nil {
		t.Errorf("tx.Meta.Err = %v, want nil", tx.Meta.Err)
	}
	if len(tx.Meta.LogMessages) != 1 || tx.Meta.LogMessages[0] != "Program log: hi" {
		t.Errorf("tx.Meta.LogMessages = %v", tx.Meta.LogMessages)
	}
}

// TestRPCClient_GetTransaction_NullResult proves a `"result":null` response
// (a signature the RPC node no longer has, or hasn't yet indexed) is
// surfaced as an explicit error rather than a nil *Tx the caller might
// dereference.
func TestRPCClient_GetTransaction_NullResult(t *testing.T) {
	srv := rpcServer(t, nil, `null`)
	defer srv.Close()

	c := NewRPCClient(srv.URL)
	_, err := c.GetTransaction(context.Background(), "missing-sig", "finalized")
	if err == nil {
		t.Fatal("expected an error for a null getTransaction result")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %v, want it to mention not found", err)
	}
}

func TestRPCClient_GetTransaction_Error(t *testing.T) {
	srv := rpcErrorServer(t, -32004, "Block not available")
	defer srv.Close()

	c := NewRPCClient(srv.URL)
	_, err := c.GetTransaction(context.Background(), "sig", "finalized")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "Block not available") {
		t.Errorf("error = %v", err)
	}
}

// --- GetLatestBlockhash ---

func TestRPCClient_GetLatestBlockhash(t *testing.T) {
	srv := rpcServer(t, func(t *testing.T, method string, params []any) {
		if method != "getLatestBlockhash" {
			t.Errorf("method = %q, want getLatestBlockhash", method)
		}
		opts := objParam(t, params, 0)
		if opts["commitment"] != "finalized" {
			t.Errorf("commitment = %v, want finalized", opts["commitment"])
		}
	}, `{"context":{"slot":1},"value":{"blockhash":"BhBase58Hash111111111111111111111111111111","lastValidBlockHeight":12345}}`)
	defer srv.Close()

	c := NewRPCClient(srv.URL)
	bh, height, err := c.GetLatestBlockhash(context.Background(), "finalized")
	if err != nil {
		t.Fatalf("GetLatestBlockhash: %v", err)
	}
	if bh != "BhBase58Hash111111111111111111111111111111" {
		t.Errorf("blockhash = %q", bh)
	}
	if height != 12345 {
		t.Errorf("lastValidBlockHeight = %d, want 12345", height)
	}
}

func TestRPCClient_GetLatestBlockhash_Error(t *testing.T) {
	srv := rpcErrorServer(t, -32000, "unhealthy")
	defer srv.Close()

	c := NewRPCClient(srv.URL)
	_, _, err := c.GetLatestBlockhash(context.Background(), "finalized")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "unhealthy") {
		t.Errorf("error = %v", err)
	}
}

// --- SendTransaction ---

func TestRPCClient_SendTransaction(t *testing.T) {
	srv := rpcServer(t, func(t *testing.T, method string, params []any) {
		if method != "sendTransaction" {
			t.Errorf("method = %q, want sendTransaction", method)
		}
		if got := strParam(t, params, 0); got != "base64-wire-tx" {
			t.Errorf("params[0] = %q, want base64-wire-tx", got)
		}
		opts := objParam(t, params, 1)
		if opts["encoding"] != "base64" {
			t.Errorf("encoding = %v, want base64", opts["encoding"])
		}
		if opts["skipPreflight"] != true {
			t.Errorf("skipPreflight = %v, want true", opts["skipPreflight"])
		}
		if opts["preflightCommitment"] != "processed" {
			t.Errorf("preflightCommitment = %v, want processed", opts["preflightCommitment"])
		}
		if opts["maxRetries"] != float64(5) {
			t.Errorf("maxRetries = %v, want 5", opts["maxRetries"])
		}
	}, `"5sigBase58xyz"`)
	defer srv.Close()

	c := NewRPCClient(srv.URL)
	sig, err := c.SendTransaction(context.Background(), "base64-wire-tx", SendTransactionOpts{
		SkipPreflight:       true,
		PreflightCommitment: "processed",
		MaxRetries:          5,
	})
	if err != nil {
		t.Fatalf("SendTransaction: %v", err)
	}
	if sig != "5sigBase58xyz" {
		t.Errorf("sig = %q, want 5sigBase58xyz", sig)
	}
}

// TestRPCClient_SendTransaction_OmitsZeroValueOptionals proves MaxRetries=0
// (Go's zero value, meaning "use the node's default") and an empty
// PreflightCommitment are left out of the request entirely, not sent as
// literal 0/"" — see SendTransactionOpts's doc comments on why 0 must not be
// distinguishable from "unset" on the wire for MaxRetries specifically.
func TestRPCClient_SendTransaction_OmitsZeroValueOptionals(t *testing.T) {
	srv := rpcServer(t, func(t *testing.T, method string, params []any) {
		opts := objParam(t, params, 1)
		if _, present := opts["maxRetries"]; present {
			t.Errorf("maxRetries present with MaxRetries=0: %v", opts["maxRetries"])
		}
		if _, present := opts["preflightCommitment"]; present {
			t.Errorf("preflightCommitment present when empty: %v", opts["preflightCommitment"])
		}
		if opts["skipPreflight"] != false {
			t.Errorf("skipPreflight = %v, want false", opts["skipPreflight"])
		}
	}, `"sig"`)
	defer srv.Close()

	c := NewRPCClient(srv.URL)
	if _, err := c.SendTransaction(context.Background(), "tx", SendTransactionOpts{}); err != nil {
		t.Fatalf("SendTransaction: %v", err)
	}
}

func TestRPCClient_SendTransaction_Error(t *testing.T) {
	srv := rpcErrorServer(t, -32002, "Transaction simulation failed")
	defer srv.Close()

	c := NewRPCClient(srv.URL)
	_, err := c.SendTransaction(context.Background(), "tx", SendTransactionOpts{})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "Transaction simulation failed") {
		t.Errorf("error = %v", err)
	}
}
