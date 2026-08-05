package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/mr-tron/base58"

	"github.com/rwa-platform/server/internal/api/dto"
	"github.com/rwa-platform/server/internal/assets"
	"github.com/rwa-platform/server/internal/auditlog"
	"github.com/rwa-platform/server/internal/auth"
	"github.com/rwa-platform/server/internal/blockchain"
	"github.com/rwa-platform/server/internal/compliance"
	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/kyc"
	"github.com/rwa-platform/server/internal/redemption"
	"github.com/rwa-platform/server/internal/sales"
)

func init() { gin.SetMode(gin.TestMode) }

const goldGramProfile = `{
  "profileVersion": "1.0",
  "projectId": "4fd4224f-6e65-4d6b-9fa9-c5c2b3514e61",
  "assetType": "allocated-gold-bar",
  "tokenUnit": "gram",
  "tokenDecimals": 18,
  "recordIdLabel": "Bar serial number",
  "assetSchema": {
    "type": "object",
    "additionalProperties": false,
    "required": ["serialNumber", "weightGrams", "purity"],
    "properties": {
      "serialNumber": { "type": "string", "minLength": 1 },
      "weightGrams": { "type": "string", "pattern": "^[0-9]+(\\.[0-9]+)?$" },
      "purity": { "type": "string", "pattern": "^[0-9]+(\\.[0-9]+)?$" }
    }
  }
}`

// Fixed, deterministic 32-byte base58 pubkeys — real Solana addresses have
// this exact shape, so any valid-looking distinct 32-byte value works as a
// fixture. Mirrors internal/config's own test fixtures.
const (
	complianceProgram = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"
	vaultProgram      = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"
	pricingProgram    = "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8"
	transferHookProg  = "GgBaCs3NCBuZN12kCJgAW63ydqohFkHEdfdEXBPzLHq"
	redemptionProgram = "LbUiWL3xVV8hTFYBVdbTNrpDo41NKS6o3LHHuDzjfcY"
	supplyController  = "QWmroo4YnnMqYW3cnxWkFdaTxGD3P7vMSzwMHGbUzwF"
	rwaMint           = "US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx"
	quoteMint         = "YMN9Qj5jPNp7j14VPcML1B6xGgcPWVZUGLFU3Mnyfaf"
	clusterGenesis    = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
	supplyConfig      = "8sN3xz2XSXo7oJ6VfBJKF4G8VZ7pJZcFmqjWpZBAeZZ5"
	vaultConfig       = "3n1LDeUZm2q7NwiWWY6VkFpBEsWc3d2SNAhK6vAj9Fyc"
)

// fakeSubmitter is a minimal blockchain.Submitter test double —
// enough for compliance.StatusService to build and "broadcast" a
// set_status transaction without a live RPC endpoint.
type fakeSubmitter struct {
	blockhash string
	// SentTxs records every transaction handed to SendTransaction, so tests
	// that care whether a compliance transaction was actually broadcast
	// (audit_intent_test.go's fail-closed cases) can assert on it.
	SentTxs []string
}

func (f *fakeSubmitter) GetLatestBlockhash(ctx context.Context, commitment string) (string, uint64, error) {
	return f.blockhash, 12345, nil
}

func (f *fakeSubmitter) SendTransaction(ctx context.Context, base64Tx string, opts blockchain.SendTransactionOpts) (string, error) {
	f.SentTxs = append(f.SentTxs, base64Tx)
	// StatusService.SetStatus cross-checks that the signature the RPC
	// echoes back equals the one it computed locally from the signed
	// transaction (a genuine safety property — see its doc comment), so
	// this must return the ACTUAL signature the wire transaction carries,
	// not a fixed placeholder. The wire format is
	// shortvec(numSignatures) + sig1(64 bytes) + ... + message; this
	// service always produces exactly one signature, so it's the 64 bytes
	// right after the 1-byte shortvec length prefix — mirrors
	// internal/compliance/status_service_test.go's fakeSubmitter.
	raw, err := base64.StdEncoding.DecodeString(base64Tx)
	if err != nil {
		return "", err
	}
	if len(raw) < 65 {
		return "", fmt.Errorf("fakeSubmitter: wire transaction too short (%d bytes) to contain a signature", len(raw))
	}
	return base58.Encode(raw[1:65]), nil
}

type testEnv struct {
	app       *App
	router    *gin.Engine
	submitter *fakeSubmitter

	// auditorKey is the mint-attestation auditor identity: frozen as a
	// secp256k1 key rendered as a 20-byte address even on the
	// Solana path — see BRIEF's "what is NOT EVM" note.
	auditorKey *ecdsa.PrivateKey

	// Admin auth (Solana wallet-signature -> JWT). adminPriv signs admin
	// login challenges (raw ed25519, no personal_sign-style prefix — see
	// auth.Verifier); adminAddr (base58) is the configured admin; jwtSecret
	// signs JWTs; bearer is a ready-to-use "Authorization: Bearer <jwt>"
	// header value for the admin, so tests exercising admin-only routes
	// just pass {"Authorization": env.bearer}.
	adminPriv ed25519.PrivateKey
	adminAddr string
	jwtSecret []byte
	bearer    string
}

func setupTestApp(t *testing.T) *testEnv {
	t.Helper()
	repos := memory.New()

	// Seed project + profile.
	result, profile := assets.ValidateProfile([]byte(goldGramProfile))
	if !result.Valid {
		t.Fatalf("profile fixture invalid: %v", result.Errors)
	}
	ctx := context.Background()

	if err := repos.AssetProfiles.Upsert(ctx, &models.AssetProfile{
		ProjectID: profile.ProjectID, ProfileRaw: []byte(goldGramProfile), Digest: profile.DigestHex(), CID: profile.CID,
		TokenDecimals: profile.TokenDecimals, TokenUnit: profile.TokenUnit, RecordIDLabel: profile.RecordIDLabel, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := repos.Projects.Upsert(ctx, &models.Project{
		ProjectID: profile.ProjectID, Version: "rwa-v2", ChainID: 901, ProfileDigest: profile.DigestHex(),
		Addresses: models.Addresses{
			SupplyController: supplyController, Vault: vaultProgram, RedemptionEscrow: redemptionProgram,
			Token: rwaMint, QuoteToken: quoteMint, Strategy: pricingProgram, Compliance: complianceProgram,
		},
		Status: models.ProjectStatusActive, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	auditorKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	auditor := crypto.PubkeyToAddress(auditorKey.PublicKey)

	_, complianceKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	records, err := assets.NewRecordService(
		repos.AssetRecords, repos.AuditPackages, repos.Attestations, nil,
		clusterGenesis, supplyController, supplyConfig, vaultConfig,
		auditor,
	)
	if err != nil {
		t.Fatal(err)
	}
	verifier := auth.NewVerifier()
	challenges := compliance.NewChallengeService(repos.WalletChallenges, repos.Investors, time.Hour, "RWA Test Platform", verifier)
	webhooks := compliance.NewWebhookService(repos.KYCEvents, repos.Investors, "webhook-secret")
	// The generic ("none") KYC provider verifies the same X-Webhook-Signature
	// HMAC shape these tests exercise; buildApp wires KYC + Webhooks
	// together, so the test App does too.
	kycProvider, _ := kyc.New(kyc.Config{Mode: kyc.ModeNone, GenericHMACSecret: "webhook-secret"})
	submitter := &fakeSubmitter{blockhash: pricingProgram}
	status, err := compliance.NewStatusService(submitter, repos.Transactions, complianceProgram, complianceKey, "finalized")
	if err != nil {
		t.Fatal(err)
	}
	salesSvc := sales.New(repos.Purchases)
	redemptionSvc := redemption.New(repos.RedemptionRequests)

	_, adminPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	adminAddr := base58.Encode(adminPriv.Public().(ed25519.PublicKey))
	jwtSecret := []byte("test-jwt-secret-that-is-at-least-32-bytes-long")

	app := &App{
		Repos:                   repos,
		ChainID:                 901,
		ProgramCompliance:       complianceProgram,
		ProgramVault:            vaultProgram,
		ProgramPricing:          pricingProgram,
		ProgramTransferHook:     transferHookProg,
		ProgramRedemption:       redemptionProgram,
		ProgramSupplyController: supplyController,
		RWAMint:                 rwaMint,
		QuoteMint:               quoteMint,
		MaxCheckpointAge:        5 * time.Minute,
		Project:                 nil, Records: records, Challenges: challenges, Webhooks: webhooks, KYC: kycProvider, Status: status,
		Sales: salesSvc, Redemptions: redemptionSvc, Audit: auditlog.New(repos.AuditLogs),
		Sessions:              auth.NewSessionManager(repos.WalletSessions, 15*time.Minute),
		AdminChallenges:       auth.NewAdminChallengeService(repos.AdminChallenges, time.Hour, "RWA Test Platform", verifier),
		AdminAddress:          adminAddr,
		JWTSecret:             jwtSecret,
		JWTTTL:                time.Hour,
		IdempotencyTTL:        time.Hour,
		FinalityConfirmations: 3,
		LastIndexedBlock:      func() uint64 { return 100 },
	}
	router := NewRouter(app)

	token, _, err := auth.IssueAdminJWT(jwtSecret, adminAddr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	return &testEnv{
		app: app, router: router, submitter: submitter, auditorKey: auditorKey,
		adminPriv: adminPriv, adminAddr: adminAddr, jwtSecret: jwtSecret, bearer: "Bearer " + token,
	}
}

// seedFreshComplianceCheckpoint records a just-polled IndexerCheckpoint for
// env.app's configured compliance program, so App.complianceStale
// reports fresh rather than its ErrNotFound/never-polled fail-closed
// default (see TestBeneficiaryAllowedFailsClosedWithNoComplianceCheckpointYet).
// setupTestApp deliberately does NOT seed one itself — several tests
// specifically exercise that fail-closed default — so any test whose point
// is the underlying investor-record lookup, not checkpoint staleness, must
// call this first.
func seedFreshComplianceCheckpoint(t *testing.T, env *testEnv) {
	t.Helper()
	if err := env.app.Repos.IndexerCheckpoints.Set(context.Background(), &models.IndexerCheckpoint{
		ChainID: env.app.ChainID, Address: env.app.ProgramCompliance,
		LastBlock: 1, LastSuccessfulPollAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}

// randomPubkey generates a fresh, valid-shaped base58 Solana pubkey for tests
// that just need a distinct wallet address, not a working keypair.
func randomPubkey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base58.Encode(pub)
}

// addr expands a short hex suffix into a full, valid checksummed EVM-shaped
// address string — still used for the auditor identity (frozen secp256k1,
// see the eip712 package) and other 20-byte-address fixtures unrelated to wallet auth.
func addr(shortHex string) string {
	return common.HexToAddress(shortHex).Hex()
}

func doJSON(t *testing.T, router *gin.Engine, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestHealthAndReady(t *testing.T) {
	env := setupTestApp(t)
	w := doJSON(t, env.router, http.MethodGet, "/healthz", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("healthz status = %d", w.Code)
	}

	// Default-deny — with no ReadyCheck wired (chain services
	// unavailable), /readyz must report not_ready, never "ready" by omission.
	w = doJSON(t, env.router, http.MethodGet, "/readyz", nil, nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz status with no ReadyCheck = %d, want 503 (default-deny)", w.Code)
	}

	// With a passing ReadyCheck it reports ready.
	env.app.ReadyCheck = func() error { return nil }
	w = doJSON(t, env.router, http.MethodGet, "/readyz", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("readyz status with passing ReadyCheck = %d, want 200", w.Code)
	}

	// A failing ReadyCheck reports not_ready.
	env.app.ReadyCheck = func() error { return errTestNotReady }
	w = doJSON(t, env.router, http.MethodGet, "/readyz", nil, nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz status with failing ReadyCheck = %d, want 503", w.Code)
	}
	// /readyz is unauthenticated, so it must never reflect the raw internal
	// error — those wrap RPC/Mongo dial failures with host:port detail.
	if strings.Contains(w.Body.String(), errTestNotReady.Error()) {
		t.Fatalf("readyz body leaked the internal error text: %s", w.Body.String())
	}

	// Each classified failure maps to a fixed, non-revealing label.
	for _, tc := range []struct {
		err  error
		want string
	}{
		{errors.New("solana rpc: dial tcp 10.0.0.7:8899: connection refused"), "chain unavailable"},
		{errors.New("storage: ping mongo-primary.internal:27017: timeout"), "storage unavailable"},
		{errors.New("solana indexer: compliance program has not completed its first poll yet"), "indexer unavailable"},
		{errTestNotReady, "not ready"},
	} {
		env.app.ReadyCheck = func() error { return tc.err }
		w = doJSON(t, env.router, http.MethodGet, "/readyz", nil, nil)
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode readyz body: %v", err)
		}
		if body["reason"] != tc.want {
			t.Fatalf("readyz reason for %v = %v, want %q", tc.err, body["reason"], tc.want)
		}
	}
}

var errTestNotReady = errors.New("test: not ready")

func TestValidateProfileEndpoint(t *testing.T) {
	env := setupTestApp(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/profile/validate", bytes.NewReader([]byte(goldGramProfile)))
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var result assets.ValidationResult
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Valid {
		t.Fatalf("expected valid, errors=%v", result.Errors)
	}
}

// goldGramProfileOtherProject is goldGramProfile with a distinct projectId
// that setupTestApp never seeds, so tests below can tell "already stored by
// the fixture" apart from "just persisted by this request".
const goldGramProfileOtherProject = `{
  "profileVersion": "1.0",
  "projectId": "11111111-2222-3333-4444-555555555555",
  "assetType": "allocated-gold-bar",
  "tokenUnit": "gram",
  "tokenDecimals": 18,
  "recordIdLabel": "Bar serial number",
  "assetSchema": {
    "type": "object",
    "additionalProperties": false,
    "required": ["serialNumber", "weightGrams", "purity"],
    "properties": {
      "serialNumber": { "type": "string", "minLength": 1 },
      "weightGrams": { "type": "string", "pattern": "^[0-9]+(\\.[0-9]+)?$" },
      "purity": { "type": "string", "pattern": "^[0-9]+(\\.[0-9]+)?$" }
    }
  }
}`

// TestValidateProfileIsPure checks that POST
// /api/v1/profile/validate — reachable with no API key at all (a missing
// key reads as RoleReadOnly, not rejected) — must never write to the
// AssetProfiles repository, even for a valid, well-formed profile.
func TestValidateProfileIsPure(t *testing.T) {
	env := setupTestApp(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/profile/validate", bytes.NewReader([]byte(goldGramProfileOtherProject)))
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var result assets.ValidationResult
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Valid {
		t.Fatalf("expected valid, errors=%v", result.Errors)
	}

	if _, err := env.app.Repos.AssetProfiles.Get(context.Background(), "11111111-2222-3333-4444-555555555555"); err == nil {
		t.Fatal("validateProfile must not persist the submitted profile")
	}
}

// TestCreateProfileRequiresAdmin covers the persistence path: it is
// admin-only, unlike the old implicit validate-then-upsert.
func TestCreateProfileRequiresAdmin(t *testing.T) {
	env := setupTestApp(t)

	for _, tc := range []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"no token", nil, http.StatusForbidden},
		{"invalid bearer", map[string]string{"Authorization": "Bearer not-a-jwt"}, http.StatusForbidden},
		{"admin jwt", map[string]string{"Authorization": env.bearer, "Idempotency-Key": "create-profile-admin"}, http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/profile", bytes.NewReader([]byte(goldGramProfileOtherProject)))
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			env.router.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d, body=%s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// TestCreateProfileIsCreateOnce is the create-once/CAS case: a second create
// for the same projectId must be rejected (409), never silently overwritten.
func TestCreateProfileIsCreateOnce(t *testing.T) {
	env := setupTestApp(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/profile", bytes.NewReader([]byte(goldGramProfileOtherProject)))
	req.Header.Set("Authorization", env.bearer)
	req.Header.Set("Idempotency-Key", "create-once-1")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("first create status = %d, body=%s", w.Code, w.Body.String())
	}

	// A DIFFERENT Idempotency-Key for the second call: the point of this
	// test is that the handler actually re-executes and hits the real
	// create-once conflict, not that an idempotency cache replays the
	// first call's 201.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/profile", bytes.NewReader([]byte(goldGramProfileOtherProject)))
	req.Header.Set("Authorization", env.bearer)
	req.Header.Set("Idempotency-Key", "create-once-2")
	w = httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("second create status = %d, want 409, body=%s", w.Code, w.Body.String())
	}
}

// TestCreateProfileGateRejectsMismatchedProjectId: when the server has a
// configured project_id, a profile whose projectId differs is rejected (400) —
// the safety gate that fixes which deployment a profile can belong to.
func TestCreateProfileGateRejectsMismatchedProjectId(t *testing.T) {
	env := setupTestApp(t)
	env.app.ProjectID = "99999999-8888-7777-6666-555555555555" // not goldGramProfileOtherProject's id

	req := httptest.NewRequest(http.MethodPost, "/api/v1/profile", bytes.NewReader([]byte(goldGramProfileOtherProject)))
	req.Header.Set("Authorization", env.bearer)
	req.Header.Set("Idempotency-Key", "gate-mismatch")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", w.Code, w.Body.String())
	}
	if _, err := env.app.Repos.AssetProfiles.Get(context.Background(), "11111111-2222-3333-4444-555555555555"); err == nil {
		t.Fatal("a gated-out profile must not be persisted")
	}
}

// TestCreateProfileGateAcceptsMatchingProjectId: the same request with the
// server configured to the profile's own projectId is accepted.
func TestCreateProfileGateAcceptsMatchingProjectId(t *testing.T) {
	env := setupTestApp(t)
	env.app.ProjectID = "11111111-2222-3333-4444-555555555555"

	req := httptest.NewRequest(http.MethodPost, "/api/v1/profile", bytes.NewReader([]byte(goldGramProfileOtherProject)))
	req.Header.Set("Authorization", env.bearer)
	req.Header.Set("Idempotency-Key", "gate-match")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", w.Code, w.Body.String())
	}
}

// otherProjectID is goldGramProfileOtherProject's own projectId. The
// on-chain-digest tests below re-point the seeded Project at it so that
// document is the one that would genuinely become this deployment's profile
// (setupTestApp's own project already has a stored profile, which would trip
// the create-once 409 before the digest check could be reached).
const otherProjectID = "11111111-2222-3333-4444-555555555555"

// seedProjectDigest re-points the singleton Project at
// goldGramProfileOtherProject's projectId and pins the given on-chain
// profileDigest on it, standing in for what project.SeedProject persists after
// cmd/platform reads the rwa-supply-controller Config account at boot.
func seedProjectDigest(t *testing.T, env *testEnv, digest string) {
	t.Helper()
	p, err := env.app.Repos.Projects.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p.ProjectID = otherProjectID
	p.ProfileDigest = digest
	if err := env.app.Repos.Projects.Upsert(context.Background(), p); err != nil {
		t.Fatal(err)
	}
}

// TestCreateProfileRejectsOnChainDigestMismatch is the create-time half of the
// profile cross-check: a profile that does not hash to the digest this
// deployment committed to on-chain at bootstrap must be refused BEFORE it is
// stored. Storing it would be unrecoverable through the API — the profile is
// create-once, so every later attempt gets the create-once 409 instead — and
// the mismatch would otherwise stay hidden until a mint broadcast failed
// on-chain, after the whole offline auditor signing round-trip.
func TestCreateProfileRejectsOnChainDigestMismatch(t *testing.T) {
	env := setupTestApp(t)
	seedProjectDigest(t, env, "0x"+strings.Repeat("ab", 32)) // not this profile's digest

	req := httptest.NewRequest(http.MethodPost, "/api/v1/profile", bytes.NewReader([]byte(goldGramProfileOtherProject)))
	req.Header.Set("Authorization", env.bearer)
	req.Header.Set("Idempotency-Key", "digest-gate-mismatch")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", w.Code, w.Body.String())
	}
	// The whole point of checking before the write: nothing may be persisted.
	if _, err := env.app.Repos.AssetProfiles.Get(context.Background(), otherProjectID); err == nil {
		t.Fatal("a digest-mismatched profile must not be persisted")
	}
}

// TestCreateProfileAcceptsMatchingOnChainDigest is the same setup with the
// digest the profile actually hashes to — proving the gate keys on the digest
// itself and doesn't just reject everything once a digest is on record.
func TestCreateProfileAcceptsMatchingOnChainDigest(t *testing.T) {
	env := setupTestApp(t)
	result, profile := assets.ValidateProfile([]byte(goldGramProfileOtherProject))
	if !result.Valid || profile == nil {
		t.Fatalf("profile fixture invalid: %v", result.Errors)
	}
	seedProjectDigest(t, env, result.ProfileDigest)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/profile", bytes.NewReader([]byte(goldGramProfileOtherProject)))
	req.Header.Set("Authorization", env.bearer)
	req.Header.Set("Idempotency-Key", "digest-gate-match")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", w.Code, w.Body.String())
	}
}

// TestCreateProfileSkipsDigestCheckWhenUnknown: a deployment whose
// supply-controller has not been `initialize`d yet (or whose boot could not
// reach the chain) has no digest on record, and must stay usable rather than
// refusing every profile. This is the same "empty means unknown" rule
// project.SeedParams.ProfileDigest and loadVerifiedProfile both follow.
func TestCreateProfileSkipsDigestCheckWhenUnknown(t *testing.T) {
	env := setupTestApp(t)
	seedProjectDigest(t, env, "")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/profile", bytes.NewReader([]byte(goldGramProfileOtherProject)))
	req.Header.Set("Authorization", env.bearer)
	req.Header.Set("Idempotency-Key", "digest-gate-unknown")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", w.Code, w.Body.String())
	}
}

// TestRecordCreationBlockedOnProfileDigestMismatch is the cross-check
// case: if the stored profile's digest ever diverges from the
// project's persisted (on-chain-submitted) profileDigest, every downstream
// record/package/signature operation must refuse rather than silently use
// the mismatched profile.
func TestRecordCreationBlockedOnProfileDigestMismatch(t *testing.T) {
	env := setupTestApp(t)
	p, err := env.app.Repos.Projects.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p.ProfileDigest = "0x" + strings.Repeat("ab", 32) // deliberately wrong
	if err := env.app.Repos.Projects.Upsert(context.Background(), p); err != nil {
		t.Fatal(err)
	}

	w := doJSON(t, env.router, http.MethodPost, "/api/v1/assets/records",
		map[string]any{"recordId": "rec-1", "asset": map[string]string{"serialNumber": "x", "weightGrams": "1", "purity": "1"}, "amount": "1000000000000000000"},
		map[string]string{"Authorization": env.bearer, "Idempotency-Key": "digest-mismatch-1"})
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", w.Code, w.Body.String())
	}
}

func TestGetProject(t *testing.T) {
	env := setupTestApp(t)
	w := doJSON(t, env.router, http.MethodGet, "/api/v1/project", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var p dto.ProjectResponse
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.ChainID != 901 {
		t.Errorf("ChainID = %d", p.ChainID)
	}
	// The security-authority snapshot must be flagged as not-guaranteed-
	// live, so the UI never presents it as current chain state.
	if !p.SecurityStale {
		t.Error("expected securityStale = true (authority fields are a deployment-time snapshot)")
	}
}

func TestComplianceChallengeFlow(t *testing.T) {
	env := setupTestApp(t)
	walletAddr := randomPubkey(t)

	w := doJSON(t, env.router, http.MethodPost, "/api/v1/compliance/challenge", map[string]string{"address": walletAddr}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var ch dto.ChallengeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	if ch.Address != walletAddr {
		t.Errorf("Address = %s", ch.Address)
	}
	if ch.Nonce == "" {
		t.Error("expected non-empty nonce")
	}
}

func TestComplianceSetStatusRequiresRole(t *testing.T) {
	env := setupTestApp(t)
	body := SetStatusRequestBody{Address: randomPubkey(t), Status: "Allowed"}
	w := doJSON(t, env.router, http.MethodPost, "/api/v1/compliance/status", body, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 without admin/operator key", w.Code)
	}
}

func TestComplianceSetStatusSubmitsTx(t *testing.T) {
	env := setupTestApp(t)

	body := SetStatusRequestBody{Address: randomPubkey(t), Status: "Allowed", ValidUntil: 0}
	w := doJSON(t, env.router, http.MethodPost, "/api/v1/compliance/status", body, map[string]string{"Authorization": env.bearer, "Idempotency-Key": "set-status-submits-tx"})
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var ref dto.TxRef
	if err := json.Unmarshal(w.Body.Bytes(), &ref); err != nil {
		t.Fatal(err)
	}
	if ref.TxHash == "" {
		t.Error("expected non-empty txHash")
	}
}

// TestIdempotencyKeyRequiredAtAPILayer is the HTTP-level check: a
// side-effecting route wired with auth.Idempotency must reject a request with
// no Idempotency-Key header, using the stable
// CodeIdempotencyKeyRequired code, before the handler (and its side
// effect) ever runs.
func TestIdempotencyKeyRequiredAtAPILayer(t *testing.T) {
	env := setupTestApp(t)

	body := SetStatusRequestBody{Address: randomPubkey(t), Status: "Allowed"}
	w := doJSON(t, env.router, http.MethodPost, "/api/v1/compliance/status", body, map[string]string{"Authorization": env.bearer})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a missing Idempotency-Key, body=%s", w.Code, w.Body.String())
	}
	var resp dto.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != CodeIdempotencyKeyRequired {
		t.Errorf("code = %q, want %q", resp.Code, CodeIdempotencyKeyRequired)
	}
}

func TestComplianceStatusIdempotency(t *testing.T) {
	env := setupTestApp(t)

	body := SetStatusRequestBody{Address: randomPubkey(t), Status: "Allowed"}
	headers := map[string]string{"Authorization": env.bearer, "Idempotency-Key": "idem-1"}
	w1 := doJSON(t, env.router, http.MethodPost, "/api/v1/compliance/status", body, headers)
	w2 := doJSON(t, env.router, http.MethodPost, "/api/v1/compliance/status", body, headers)
	if w1.Code != http.StatusAccepted || w2.Code != http.StatusAccepted {
		t.Fatalf("codes: %d, %d", w1.Code, w2.Code)
	}
	if w1.Body.String() != w2.Body.String() {
		t.Errorf("expected identical replayed response, got %s vs %s", w1.Body.String(), w2.Body.String())
	}
}

func TestAssetsCreateListPackageAndSignatureFlow(t *testing.T) {
	env := setupTestApp(t)

	createBody := CreateRecordRequestBody{
		RecordID: "GOLD-BAR-API-1",
		Asset:    json.RawMessage(`{"serialNumber":"1","weightGrams":"250","purity":"999.9"}`),
		// Solana mint amounts are u64 (see eip712.Amount's bound) —
		// unlike an EVM uint256, this must fit in 64 bits. 250 whole tokens
		// at 9 decimals (a realistic SPL Token-2022 decimals count) is well
		// within range, unlike an 18-decimals-scaled amount.
		Amount: "250000000000",
	}
	w := doJSON(t, env.router, http.MethodPost, "/api/v1/assets/records", createBody, map[string]string{"Authorization": env.bearer, "Idempotency-Key": "flow-create-1"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", w.Code, w.Body.String())
	}
	var created dto.AssetRecordResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	w = doJSON(t, env.router, http.MethodGet, "/api/v1/assets/records", nil, map[string]string{"Authorization": env.bearer})
	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d", w.Code)
	}
	var listed []dto.AssetRecordResponse
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 {
		t.Fatalf("expected 1 record, got %d", len(listed))
	}

	w = doJSON(t, env.router, http.MethodGet, "/api/v1/assets/records/"+created.RecordID+"/package", nil, map[string]string{"Authorization": env.bearer})
	if w.Code != http.StatusOK {
		t.Fatalf("package status = %d, body=%s", w.Code, w.Body.String())
	}
	if w.Header().Get("Content-Type") != "application/zip" {
		t.Errorf("Content-Type = %s", w.Header().Get("Content-Type"))
	}
	if w.Body.Len() == 0 {
		t.Error("expected non-empty package bytes")
	}
}

// TestDownloadPackageRejectsRejectedRecord covers
// package build: a Rejected record will never be minted, so building a
// package for it is pointless — unlike Signed/Minted/expired-but-otherwise-
// valid records, which downloadPackage still serves (see its handler's
// doc comment for why those are allowed: no chain interaction, useful as
// an audit-trail lookup).
func TestDownloadPackageRejectsRejectedRecord(t *testing.T) {
	env := setupTestApp(t)
	ctx := context.Background()

	createBody := CreateRecordRequestBody{
		RecordID: "GOLD-BAR-L03-REJECTED",
		Asset:    json.RawMessage(`{"serialNumber":"5","weightGrams":"5","purity":"999.9"}`),
		Amount:   "5000000000000000000",
	}
	w := doJSON(t, env.router, http.MethodPost, "/api/v1/assets/records", createBody, map[string]string{"Authorization": env.bearer, "Idempotency-Key": "rejected-create"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", w.Code, w.Body.String())
	}

	rec, err := env.app.Repos.AssetRecords.Get(ctx, "GOLD-BAR-L03-REJECTED")
	if err != nil {
		t.Fatal(err)
	}
	rec.Status = models.RecordStatusRejected
	if err := env.app.Repos.AssetRecords.Update(ctx, rec); err != nil {
		t.Fatal(err)
	}

	w = doJSON(t, env.router, http.MethodGet, "/api/v1/assets/records/GOLD-BAR-L03-REJECTED/package", nil, map[string]string{"Authorization": env.bearer})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a Rejected record, got %d body=%s", w.Code, w.Body.String())
	}
}

// TestRedemptionIDParamAcceptsZero pins the nuance that a redemption id is
// legitimately 0, so the :id path parameter must accept 0 rather than
// rejecting it as empty/missing.
func TestRedemptionIDParamAcceptsZero(t *testing.T) {
	env := setupTestApp(t)
	w := doJSON(t, env.router, http.MethodGet, "/api/v1/redemptions/0", nil, nil)
	// No redemption with id 0 exists in this test's fixtures, so this
	// legitimately 404s — the point is it must NOT be rejected as a
	// malformed id with 400.
	if w.Code == http.StatusBadRequest {
		t.Errorf("id=0: status = 400 (rejected as a malformed id), want it to reach the lookup and 404 instead")
	}
}

func TestSalesInventory(t *testing.T) {
	env := setupTestApp(t)

	w := doJSON(t, env.router, http.MethodGet, "/api/v1/sales/inventory", nil, nil)
	// Always 501 (no server chain client — see getInventory's doc
	// comment); asserting the route is wired, not a 404.
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", w.Code)
	}
}

func TestRedemptionsList(t *testing.T) {
	env := setupTestApp(t)

	w := doJSON(t, env.router, http.MethodGet, "/api/v1/redemptions", nil, map[string]string{"Authorization": env.bearer})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var list []dto.RedemptionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d", len(list))
	}
}

func TestListTransactionsEmpty(t *testing.T) {
	env := setupTestApp(t)
	w := doJSON(t, env.router, http.MethodGet, "/api/v1/transactions", nil, map[string]string{"Authorization": env.bearer})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var list []dto.TransactionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d", len(list))
	}
}

// TestListRecordsIsPaginated checks that this list handler never fetches an
// entire Mongo collection and serializes it in one response — the server-side
// limit applies even when the client omits parameters. Seeds more records than
// the default page size and checks both the default-bounded response and an
// explicit limit/cursor walk through every page.
func TestListRecordsIsPaginated(t *testing.T) {
	env := setupTestApp(t)
	ctx := context.Background()
	const total = defaultListLimit + 7
	for i := 0; i < total; i++ {
		if err := env.app.Repos.AssetRecords.Create(ctx, &models.AssetRecord{
			RecordID: fmt.Sprintf("PAGE-%03d", i), ProjectID: "4fd4224f-6e65-4d6b-9fa9-c5c2b3514e61",
			Status: models.RecordStatusDraft, Amount: "1", CreatedAt: time.Now().Add(time.Duration(i) * time.Millisecond),
		}); err != nil {
			t.Fatal(err)
		}
	}

	// No limit/cursor supplied: the server-side default must still bound
	// the response, never returning the full collection.
	w := doJSON(t, env.router, http.MethodGet, "/api/v1/assets/records", nil, map[string]string{"Authorization": env.bearer})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var page []dto.AssetRecordResponse
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page) != defaultListLimit {
		t.Errorf("default page size = %d, want %d (server-side default must apply even with no query params)", len(page), defaultListLimit)
	}
	// This endpoint uses repository-level keyset pagination — X-Total-Count
	// is deliberately omitted (a true total would need an extra unbounded
	// count, reintroducing the exact unbounded work being removed here),
	// matching listAuditLogs' pre-existing "omitted rather than sent wrong"
	// convention.
	if w.Header().Get("X-Total-Count") != "" {
		t.Errorf("X-Total-Count = %q, want omitted", w.Header().Get("X-Total-Count"))
	}
	next := w.Header().Get("X-Next-Cursor")
	if next == "" {
		t.Fatal("expected a non-empty X-Next-Cursor since more records remain")
	}

	// Walk every remaining page via the returned cursor, collecting every
	// recordId seen, and confirm the full walk exactly covers every seeded
	// record exactly once (no gaps, no duplicates from an unstable window).
	seen := map[string]bool{}
	for _, r := range page {
		seen[r.RecordID] = true
	}
	for next != "" {
		w := doJSON(t, env.router, http.MethodGet, "/api/v1/assets/records?limit=10&cursor="+next, nil, map[string]string{"Authorization": env.bearer})
		if w.Code != http.StatusOK {
			t.Fatalf("page fetch: status = %d, body=%s", w.Code, w.Body.String())
		}
		var p []dto.AssetRecordResponse
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		if len(p) == 0 {
			t.Fatal("got an empty page while X-Next-Cursor was still set")
		}
		for _, r := range p {
			if seen[r.RecordID] {
				t.Errorf("recordId %s seen more than once across pages", r.RecordID)
			}
			seen[r.RecordID] = true
		}
		next = w.Header().Get("X-Next-Cursor")
	}
	if len(seen) != total {
		t.Errorf("paginated walk covered %d records, want %d", len(seen), total)
	}
}

// TestListRecordsRejectsOversizedLimit pins the conservative hard-maximum
// requirement: a client requesting more than maxListLimit must be capped, never
// served the raw requested amount.
func TestListRecordsRejectsOversizedLimit(t *testing.T) {
	env := setupTestApp(t)
	ctx := context.Background()
	const total = maxListLimit + 5
	for i := 0; i < total; i++ {
		if err := env.app.Repos.AssetRecords.Create(ctx, &models.AssetRecord{
			RecordID: fmt.Sprintf("CAP-%04d", i), ProjectID: "4fd4224f-6e65-4d6b-9fa9-c5c2b3514e61",
			Status: models.RecordStatusDraft, Amount: "1", CreatedAt: time.Now().Add(time.Duration(i) * time.Millisecond),
		}); err != nil {
			t.Fatal(err)
		}
	}

	w := doJSON(t, env.router, http.MethodGet, fmt.Sprintf("/api/v1/assets/records?limit=%d", total), nil, map[string]string{"Authorization": env.bearer})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var page []dto.AssetRecordResponse
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page) != maxListLimit {
		t.Errorf("page size = %d, want the hard-capped %d even though limit=%d was requested", len(page), maxListLimit, total)
	}
}

// TestAuthSessionHasItsOwnRateLimitIndependentOfGlobal checks that the
// endpoint-specific login limiter stays on independent of the optional global
// limiter. env.app never sets RateLimitRPS (the
// global limiter middleware is therefore NOT installed at all — see
// NewRouter's `if app.RateLimitRPS > 0`), yet rapid POST /auth/session
// calls must still be throttled by the endpoint-specific bucket.
func TestAuthSessionHasItsOwnRateLimitIndependentOfGlobal(t *testing.T) {
	env := setupTestApp(t)
	if env.app.RateLimitRPS > 0 {
		t.Fatal("test precondition: expected the global rate limiter to be disabled")
	}

	var last *httptest.ResponseRecorder
	throttled := false
	for i := 0; i < sessionLoginBurst+5; i++ {
		last = doJSON(t, env.router, http.MethodPost, "/auth/session", map[string]string{"address": env.adminAddr, "signature": base58.Encode(make([]byte, ed25519.SignatureSize))}, nil)
		if last.Code == http.StatusTooManyRequests {
			throttled = true
			break
		}
	}
	if !throttled {
		t.Fatalf("expected POST /auth/session to eventually return 429 within %d rapid calls, last status = %d", sessionLoginBurst+5, last.Code)
	}
}
