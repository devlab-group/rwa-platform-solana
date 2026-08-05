package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/rwa-platform/server/internal/api/dto"
	"github.com/rwa-platform/server/internal/dal/models"
)

// TestGetMyWalletStatusRequiresSession pins the auth boundary:
// /api/v1/me/wallet-status is gated by auth.RequireWalletSession, not
// X-API-Key — no header at all must 401.
func TestGetMyWalletStatusRequiresSession(t *testing.T) {
	env := setupTestApp(t)
	w := doJSON(t, env.router, http.MethodGet, "/api/v1/me/wallet-status", nil, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", w.Code, w.Body.String())
	}
}

// TestGetMyWalletStatusRejectsInvalidSessionToken pins that a garbage/
// unknown X-Wallet-Session value is rejected the same as a missing one,
// not treated as some other principal.
func TestGetMyWalletStatusRejectsInvalidSessionToken(t *testing.T) {
	env := setupTestApp(t)
	w := doJSON(t, env.router, http.MethodGet, "/api/v1/me/wallet-status", nil, map[string]string{"X-Wallet-Session": "not-a-real-token"})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", w.Code, w.Body.String())
	}
}

// TestGetMyWalletStatusReturnsOwnStatus is the core case: a
// valid session returns the WalletStatus for exactly the address bound to
// that session (seeded here as Allowed), and never requires — or accepts
// — an X-API-Key.
func TestGetMyWalletStatusReturnsOwnStatus(t *testing.T) {
	env := setupTestApp(t)
	ctx := context.Background()
	address := randomPubkey(t)

	if err := env.app.Repos.Investors.Upsert(ctx, &models.Investor{
		Address: address, Status: models.ComplianceAllowed, ValidUntil: 1900000000, OwnershipVerified: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	token, _, err := env.app.Sessions.Issue(ctx, address)
	if err != nil {
		t.Fatal(err)
	}

	w := doJSON(t, env.router, http.MethodGet, "/api/v1/me/wallet-status", nil, map[string]string{"X-Wallet-Session": token})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var got dto.WalletStatus
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Address != address || got.Status != "Allowed" || !got.OwnershipVerified {
		t.Errorf("got %+v", got)
	}
}

// TestGetMyWalletStatusUnknownForAddressWithNoRecord covers the (in
// practice unreachable via the real verifyChallenge->session flow, since
// VerifyOwnership always upserts an Investor row first) defensive fallback
// for a session whose address has no Investor record at all.
func TestGetMyWalletStatusUnknownForAddressWithNoRecord(t *testing.T) {
	env := setupTestApp(t)
	address := randomPubkey(t)
	token, _, err := env.app.Sessions.Issue(context.Background(), address)
	if err != nil {
		t.Fatal(err)
	}

	w := doJSON(t, env.router, http.MethodGet, "/api/v1/me/wallet-status", nil, map[string]string{"X-Wallet-Session": token})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var got dto.WalletStatus
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "Unknown" {
		t.Errorf("Status = %q, want Unknown", got.Status)
	}
}

// TestIsAddressAllowedIsPublicAndDisclosesOnlyAllowed covers the other
// half: no X-API-Key / no X-Wallet-Session at all, and the response body
// contains ONLY the "allowed" field — never status/validUntil/ownership,
// which would let an anonymous caller enumerate a third party's compliance
// state.
func TestIsAddressAllowedIsPublicAndDisclosesOnlyAllowed(t *testing.T) {
	env := setupTestApp(t)
	seedFreshComplianceCheckpoint(t, env)
	account := randomPubkey(t)

	if err := env.app.Repos.Investors.Upsert(context.Background(), &models.Investor{
		Address: account, Status: models.ComplianceAllowed, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	w := doJSON(t, env.router, http.MethodGet, "/api/v1/compliance/allowed/"+account, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}

	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 1 {
		t.Fatalf("expected exactly one field in the response, got %v", raw)
	}
	allowed, ok := raw["allowed"].(bool)
	if !ok || !allowed {
		t.Errorf("allowed = %v (ok=%v), want true", raw["allowed"], ok)
	}
}

// TestIsAddressAllowedReflectsFalse exercises the other outcome so the
// handler isn't just always returning true.
func TestIsAddressAllowedReflectsFalse(t *testing.T) {
	env := setupTestApp(t)
	account := randomPubkey(t)

	if err := env.app.Repos.Investors.Upsert(context.Background(), &models.Investor{
		Address: account, Status: models.ComplianceBlocked, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	w := doJSON(t, env.router, http.MethodGet, "/api/v1/compliance/allowed/"+account, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var got dto.AllowedResult
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Allowed {
		t.Error("expected allowed=false")
	}
}

func TestIsAddressAllowedRejectsBadAddress(t *testing.T) {
	env := setupTestApp(t)
	w := doJSON(t, env.router, http.MethodGet, "/api/v1/compliance/allowed/not-an-address", nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// TestIsAddressAllowedUsesIndexedInvestorStatus covers the read
// path: there is no server-held chain client to read
// ComplianceRegistry.isAllowed from, so it must consult the indexed investor
// record (the same one compliance.Reconcile keeps live) instead — a
// valid base58 pubkey with Status=Allowed on file reports allowed=true.
func TestIsAddressAllowedUsesIndexedInvestorStatus(t *testing.T) {
	env := setupTestApp(t)
	seedFreshComplianceCheckpoint(t, env)
	const account = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"

	if err := env.app.Repos.Investors.Upsert(context.Background(), &models.Investor{
		Address: account, Status: models.ComplianceAllowed, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	w := doJSON(t, env.router, http.MethodGet, "/api/v1/compliance/allowed/"+account, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var got dto.AllowedResult
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Allowed {
		t.Error("expected allowed=true from the indexed investor record")
	}
}

// TestIsAddressAllowedNoRecordDefaultsFalse: an address with no
// indexed investor record yet must report allowed=false, not an error.
func TestIsAddressAllowedNoRecordDefaultsFalse(t *testing.T) {
	env := setupTestApp(t)
	const account = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"

	w := doJSON(t, env.router, http.MethodGet, "/api/v1/compliance/allowed/"+account, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var got dto.AllowedResult
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Allowed {
		t.Error("expected allowed=false with no indexed investor record")
	}
}

// TestIsAddressAllowedRejectsHexAddress: a caller-supplied address must be
// validated as base58 (not 0x-hex) — an EVM-shaped address is not a valid
// Solana pubkey and must 400, not be silently misread.
func TestIsAddressAllowedRejectsHexAddress(t *testing.T) {
	env := setupTestApp(t)
	w := doJSON(t, env.router, http.MethodGet, "/api/v1/compliance/allowed/"+addr("0xB0B0"), nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400, body=%s", w.Code, w.Body.String())
	}
}
