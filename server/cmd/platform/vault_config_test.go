package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/mr-tron/base58"

	"github.com/rwa-platform/server/internal/blockchain"
	"github.com/rwa-platform/server/internal/config"
	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
)

// Fixture base58 pubkeys for TestBuildAppWiresVaultConfigNotVaultProgram
// below. fxVaultConfigPDA is deliberately a DIFFERENT pubkey from
// fxVaultProgramID: the regression this guards against was exactly these
// two getting collapsed into one value inside buildApp's wiring, so
// the test only proves
// anything if the fixtures themselves stay distinct.
const (
	fxVaultProgramID   = "VauLT1111111111111111111111111111111111111"
	fxVaultConfigPDA   = "3n1LDeUZm2q7NwiWWY6VkFpBEsWc3d2SNAhK6vAj9Fyc"
	fxSupplyController = "SuppLyCtR1111111111111111111111111111111111"
	fxSupplyConfig     = "8sN3xz2XSXo7oJ6VfBJKF4G8VZ7pJZcFmqjWpZBAeZZ5"
	fxClusterGenesis   = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
	fxCompliance       = "CompLiance111111111111111111111111111111111"
	fxPricing          = "PriciNg111111111111111111111111111111111111"
	fxRedemption       = "REdempT10n1111111111111111111111111111111"
	fxRWAMint          = "US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx"
	fxQuoteMint        = "YMN9Qj5jPNp7j14VPcML1B6xGgcPWVZUGLFU3Mnyfaf"
	// fxAdminPubkey is a valid 32-byte base58 pubkey (unlike some of the
	// human-mnemonic-style fixtures above, which are legitimately shorter
	// than 32 decoded bytes because nothing else in this file ever
	// base58-decodes them) — verifyVaultConfigOnChain's tests
	// below DO decode this one, so it must be exactly 32 bytes.
	fxAdminPubkey = "Bswb3UyeD1pUTaGiE6WvqwFpJZsQSEY1xhJePCDTHdvp"
	// fxProfileDigest is fxProfileDigestBytes' 0x-hex form — the exact string
	// verifyVaultConfigOnChain must return on the success path.
	fxProfileDigest = "0x101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
)

// fxProfileDigestBytes is the 32-byte profile_digest validConfigAccountData
// places at configProfileDigestOffset. Deliberately a RUNNING SEQUENCE rather
// than a repeated byte: profile_digest sits between two other 32-byte fields
// (registry at 156, cluster at 220), so a value like 0xAA…AA would still
// "match" if the offset were off by a whole field, which is exactly the class
// of bug the offset constants exist to prevent. With this pattern a wrong
// offset reads zeros (or a base58 pubkey's bytes) and the test fails.
var fxProfileDigestBytes = func() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(0x10 + i)
	}
	return b
}()

// TestBuildAppWiresVaultConfigNotVaultProgram is an end-to-end
// regression guard: it drives buildApp — the actual
// cmd/platform wiring path main() uses, not the isolated
// NewRecordService call assets/attestation_test.go already covers
// — and asserts the resulting typed-data.json's message.vault is
// cfg.VaultConfig (the rwa-vault Config PDA), never
// cfg.ProgramVault (the vault PROGRAM id). This mix-up escaped every prior
// test specifically because they all constructed the record service
// directly with a chosen vault value rather than exercising this wiring, so
// this test's whole point is to fail if buildApp's argument order (or
// which config field it reads) ever regresses.
func TestBuildAppWiresVaultConfigNotVaultProgram(t *testing.T) {
	cfg := config.Config{
		ChainID:                 900001,
		Commitment:              "finalized",
		ProgramCompliance:       fxCompliance,
		ProgramVault:            fxVaultProgramID,
		ProgramPricing:          fxPricing,
		ProgramRedemption:       fxRedemption,
		ProgramSupplyController: fxSupplyController,
		RWAMint:                 fxRWAMint,
		QuoteMint:               fxQuoteMint,
		ClusterGenesis:          fxClusterGenesis,
		SupplyConfig:            fxSupplyConfig,
		VaultConfig:             fxVaultConfigPDA,
	}
	repos := memory.New()
	// Never dialed during construction — buildApp only captures this
	// client in closures (ReadyCheck, the optional compliance status
	// service) that this test never invokes.
	client := blockchain.NewRPCClient("http://127.0.0.1:0")
	app, providers := buildApp(cfg, repos, client, nil, common.Address{})
	if len(providers) != 0 {
		t.Fatalf("buildApp returned %d key providers, want 0 (see its doc comment)", len(providers))
	}
	if app.Records == nil {
		t.Fatal("app.Records is nil; NewRecordService failed to construct with valid fixture pubkeys")
	}

	// BuildMintAttestation fails closed on a zero auditor (a package with one
	// is unsignable), so give it a real one — this test is about the VAULT
	// wiring, not the auditor.
	app.Records.SetBaselineAuditor(common.HexToAddress("0x00000000000000000000000000000000000aa11"))

	record := &models.AssetRecord{
		RecordID:       "vault-config-regression",
		RecordKey:      "0x" + strings.Repeat("11", 32),
		MetadataDigest: "0x" + strings.Repeat("22", 32),
		Amount:         "1000",
		Nonce:          "1",
		ValidUntil:     0,
	}
	doc, _, err := app.Records.BuildMintAttestation(record, [32]byte{})
	if err != nil {
		t.Fatalf("BuildMintAttestation: %v", err)
	}

	if doc.Message.Vault != fxVaultConfigPDA {
		t.Errorf("typed-data.json message.vault = %q, want the configured vault-config PDA %q", doc.Message.Vault, fxVaultConfigPDA)
	}
	// A cheap structural guard: re-introducing the
	// confusion (wiring ProgramVault instead of VaultConfig)
	// must fail this test loudly, not just disagree with the exact-value
	// assertion above.
	if doc.Message.Vault == cfg.ProgramVault {
		t.Fatalf("typed-data.json message.vault equals the vault PROGRAM id %q — regression: buildApp is binding the mint attestation to the wrong account", cfg.ProgramVault)
	}
}

// getAccountInfoServer starts a minimal JSON-RPC httptest.Server that
// answers every request with one getAccountInfo-shaped "value" result
// (resultJSON verbatim), for verifyVaultConfigOnChain's tests below.
func getAccountInfoServer(t *testing.T, resultJSON string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":%s}`, resultJSON)
	}))
}

// accountInfoResultJSON builds a getAccountInfo "value" result JSON string
// for data/owner, for verifyVaultConfigOnChain's tests below.
func accountInfoResultJSON(data []byte, owner string) string {
	return fmt.Sprintf(`{"value":{"data":[%q,"base64"],"owner":%q}}`, base64.StdEncoding.EncodeToString(data), owner)
}

// validConfigAccountData builds a fake rwa-supply-controller Config
// account's raw bytes: EXACTLY configAccountSize bytes (matching the
// exact-size guard verifyVaultConfigOnChain enforces), with the real
// Anchor Config discriminator at offset 0 and vault/admin/token_mint/cluster/
// profile_digest placed at their real field offsets (see
// verifyVaultConfigOnChain's offset-constant doc comment) — every other byte
// zeroed, which is fine since the function under test never reads
// pending_admin/auditor_eth/registry/finalized/bump.
func validConfigAccountData(t *testing.T) []byte {
	t.Helper()
	data := make([]byte, configAccountSize)
	copy(data[:8], configDiscriminator[:])
	copy(data[configProfileDigestOffset:], fxProfileDigestBytes)
	place := func(offset int, pubkey string) {
		b, err := base58.Decode(pubkey)
		if err != nil || len(b) != 32 {
			t.Fatalf("decoding fixture pubkey %q: %v", pubkey, err)
		}
		copy(data[offset:], b)
	}
	place(configAdminOffset, fxAdminPubkey)
	place(configTokenMintOffset, fxRWAMint)
	place(configVaultOffset, fxVaultConfigPDA)
	place(configClusterOffset, fxClusterGenesis)
	return data
}

// fxVerifyConfig is the config.Config verifyVaultConfigOnChain's
// tests below drive against a validConfigAccountData()-shaped fixture —
// every field that function cross-checks has a corresponding value here so
// the "fully valid account" case actually exercises every check.
var fxVerifyConfig = config.Config{
	SupplyConfig: fxSupplyConfig, VaultConfig: fxVaultConfigPDA,
	ProgramSupplyController: fxSupplyController,
	RWAMint:                 fxRWAMint, ClusterGenesis: fxClusterGenesis, AdminPubkey: fxAdminPubkey,
	Commitment: "finalized",
}

// TestVerifyVaultConfigOnChainMatch covers the full success path: a
// genuine account (correct owner, discriminator, exact size) whose vault,
// token_mint, cluster, and admin fields all match cfg. The function must
// never call log.Fatalf itself — that decision belongs to
// the caller (runPlatform) — so this test can safely exercise every
// branch in-process, unlike the old version of this suite.
func TestVerifyVaultConfigOnChainMatch(t *testing.T) {
	srv := getAccountInfoServer(t, accountInfoResultJSON(validConfigAccountData(t), fxSupplyController))
	defer srv.Close()

	client := blockchain.NewRPCClient(srv.URL)
	digest, err := verifyVaultConfigOnChain(context.Background(), client, fxVerifyConfig)
	if err != nil {
		t.Fatalf("verifyVaultConfigOnChain: %v, want nil (every field matches)", err)
	}
	// The success path must also hand back the account's profile_digest, in
	// 0x-hex, read from configProfileDigestOffset — this is the value
	// project.SeedProject persists and every profile cross-check then compares
	// against, so a wrong offset here would silently disarm all of them.
	if digest != fxProfileDigest {
		t.Errorf("profile digest = %q, want %q", digest, fxProfileDigest)
	}
}

// TestConfigFieldOffsets pins the byte offsets against
// solana/programs/rwa-supply-controller/src/lib.rs's `Config` declaration,
// spelled out as literal numbers.
//
// This exists because no other test in this file can catch a wrong offset: the
// fixtures place each field AT the same constant the code under test reads it
// FROM, so a constant that is wrong in both places round-trips perfectly. Only
// a hard-coded expectation, derived independently from the Rust struct, fails.
//
// Borsh (what Anchor's #[account] derives) encodes fields in declaration order
// with no padding, so each offset is the sum of the preceding field sizes:
//
//	8 discriminator | admin 32 | pending_admin 32 | auditor_eth 20 |
//	token_mint 32 | vault 32 | registry 32 | profile_digest 32 |
//	cluster 32 | finalized 1 | bump 1  = 254
func TestConfigFieldOffsets(t *testing.T) {
	for _, tc := range []struct {
		field string
		got   int
		want  int
	}{
		{"admin", configAdminOffset, 8},
		{"token_mint", configTokenMintOffset, 92},
		{"vault", configVaultOffset, 124},
		{"profile_digest", configProfileDigestOffset, 188},
		{"cluster", configClusterOffset, 220},
		{"Config::SPACE", configAccountSize, 254},
	} {
		if tc.got != tc.want {
			t.Errorf("%s offset = %d, want %d", tc.field, tc.got, tc.want)
		}
	}
	// Every read is 32 bytes wide and must stay inside the account.
	if configProfileDigestOffset+configProfileDigestLen > configAccountSize {
		t.Errorf("profile_digest read runs past the account: %d+%d > %d",
			configProfileDigestOffset, configProfileDigestLen, configAccountSize)
	}
}

// TestVerifyVaultConfigOnChainNoDigestOnFailure pins the half of the
// contract the per-failure-mode tests below don't: on EVERY error path the
// returned digest must be empty, never a partially-read value. Persisting a
// digest scraped from an account whose owner/discriminator/size were never
// proven would be strictly worse than persisting nothing — it would arm the
// profile cross-checks with an attacker- or accident-supplied value.
func TestVerifyVaultConfigOnChainNoDigestOnFailure(t *testing.T) {
	// Each case is a genuine Config account body mutated into one specific
	// failure mode, plus the owner to serve it under.
	wrongSize := validConfigAccountData(t)[:configAccountSize-1]
	badDiscriminator := validConfigAccountData(t)
	copy(badDiscriminator[:8], []byte{9, 9, 9, 9, 9, 9, 9, 9})

	cases := []struct {
		name   string
		result string
	}{
		{"missing account", `{"value":null}`},
		{"wrong owner", accountInfoResultJSON(validConfigAccountData(t), "SomeOtherProgram11111111111111111111111111")},
		{"wrong size", accountInfoResultJSON(wrongSize, fxSupplyController)},
		{"bad discriminator", accountInfoResultJSON(badDiscriminator, fxSupplyController)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := getAccountInfoServer(t, tc.result)
			defer srv.Close()

			digest, err := verifyVaultConfigOnChain(context.Background(), blockchain.NewRPCClient(srv.URL), fxVerifyConfig)
			if err == nil {
				t.Fatal("expected a non-nil error")
			}
			if digest != "" {
				t.Errorf("profile digest = %q, want %q on the error path", digest, "")
			}
		})
	}
}

// TestVerifyVaultConfigOnChainMissingAccount covers a not-yet-
// initialized supply-controller (getAccountInfo's documented "value":null
// response). This is the state runPlatform's caller-side policy turns
// into a production startup failure (log.Fatalf, unless
// PRODUCTION_ALLOW_UNVERIFIED_SUPPLY_CONFIG overrides it) — that
// branching logic itself calls log.Fatalf and so cannot be safely
// unit-tested in-process (same reasoning the old version of this comment
// gave), but this test proves the helper's own contract: it returns a
// plain, non-nil, non-fatal error for the caller to act on, never a
// process exit.
func TestVerifyVaultConfigOnChainMissingAccount(t *testing.T) {
	srv := getAccountInfoServer(t, `{"value":null}`)
	defer srv.Close()

	client := blockchain.NewRPCClient(srv.URL)
	if _, err := verifyVaultConfigOnChain(context.Background(), client, fxVerifyConfig); err == nil {
		t.Fatal("expected a non-nil (non-fatal) error for a missing account")
	}
}

// TestVerifyVaultConfigOnChainWrongOwner is a regression test for the
// owner check: an account of exactly the right size,
// discriminator, and field values but owned by a DIFFERENT program can
// never genuinely be this deployment's Config — GetAccountInfo used to
// discard the owner entirely, so this case previously passed.
func TestVerifyVaultConfigOnChainWrongOwner(t *testing.T) {
	srv := getAccountInfoServer(t, accountInfoResultJSON(validConfigAccountData(t), "SomeOtherProgram11111111111111111111111111"))
	defer srv.Close()

	client := blockchain.NewRPCClient(srv.URL)
	_, err := verifyVaultConfigOnChain(context.Background(), client, fxVerifyConfig)
	if err == nil {
		t.Fatal("expected a non-nil error for an account owned by the wrong program")
	}
	if !strings.Contains(err.Error(), "owned by") {
		t.Errorf("error = %v, want it to mention the owner mismatch", err)
	}
}

// TestVerifyVaultConfigOnChainBadDiscriminator is a regression test
// for the Anchor discriminator check: an account of the right
// size and owner, with a genuinely matching vault field at the assumed
// offset, but whose first 8 bytes are NOT the Config discriminator — e.g. an
// unrelated account type this same program declares, or arbitrary chosen
// bytes — must be reported as "cannot verify", not treated as a match.
func TestVerifyVaultConfigOnChainBadDiscriminator(t *testing.T) {
	data := validConfigAccountData(t)
	copy(data[:8], []byte{1, 2, 3, 4, 5, 6, 7, 8}) // deliberately NOT configDiscriminator
	srv := getAccountInfoServer(t, accountInfoResultJSON(data, fxSupplyController))
	defer srv.Close()

	client := blockchain.NewRPCClient(srv.URL)
	_, err := verifyVaultConfigOnChain(context.Background(), client, fxVerifyConfig)
	if err == nil {
		t.Fatal("expected a non-nil error for a wrong discriminator")
	}
	if !strings.Contains(err.Error(), "discriminator") {
		t.Errorf("error = %v, want it to mention the discriminator mismatch", err)
	}
}

// TestVerifyVaultConfigOnChainVaultMismatch covers a genuine
// misconfiguration: a fully genuine, correctly-owned, correctly-sized
// Config account whose vault field simply disagrees with cfg.VaultConfig.
func TestVerifyVaultConfigOnChainVaultMismatch(t *testing.T) {
	data := validConfigAccountData(t)
	const otherVault = "D2ZcUbtpG5sKq7XLeB4YnpNnTGSptKCxTddoNeydzJQq" // any distinct valid 32-byte pubkey
	other, err := base58.Decode(otherVault)
	if err != nil {
		t.Fatal(err)
	}
	copy(data[configVaultOffset:], other)
	srv := getAccountInfoServer(t, accountInfoResultJSON(data, fxSupplyController))
	defer srv.Close()

	client := blockchain.NewRPCClient(srv.URL)
	_, err = verifyVaultConfigOnChain(context.Background(), client, fxVerifyConfig)
	if err == nil {
		t.Fatal("expected a non-nil error for a vault mismatch")
	}
	if !strings.Contains(err.Error(), "vault") {
		t.Errorf("error = %v, want it to mention the vault mismatch", err)
	}
}

// TestVerifyVaultConfigOnChainTooShort covers a decoded account
// shorter than configAccountSize — malformed/truncated data must be
// reported as "cannot verify", not panic on a slice-bounds access.
func TestVerifyVaultConfigOnChainTooShort(t *testing.T) {
	short := make([]byte, 8) // just a discriminator-sized prefix, nothing else
	srv := getAccountInfoServer(t, accountInfoResultJSON(short, fxSupplyController))
	defer srv.Close()

	client := blockchain.NewRPCClient(srv.URL)
	if _, err := verifyVaultConfigOnChain(context.Background(), client, fxVerifyConfig); err == nil {
		t.Fatal("expected a non-nil error for a too-short account")
	}
}

// TestVerifyVaultConfigOnChainUnexpectedSize covers the exact-size
// defense-in-depth guard (the fix for the lead's brick-risk review): an
// account long enough to contain the vault field at the assumed offset, but
// NOT exactly configAccountSize (e.g. a future on-chain program
// upgrade added/removed a field), must be reported as "cannot verify" —
// never silently read at a byte offset that might no longer mean what this
// process assumes.
func TestVerifyVaultConfigOnChainUnexpectedSize(t *testing.T) {
	// One byte longer than the exact expected size, with genuinely matching
	// fields at their assumed offsets — if the size guard were missing,
	// this would incorrectly report success.
	oversized := append(validConfigAccountData(t), 0x00)
	srv := getAccountInfoServer(t, accountInfoResultJSON(oversized, fxSupplyController))
	defer srv.Close()

	client := blockchain.NewRPCClient(srv.URL)
	if _, err := verifyVaultConfigOnChain(context.Background(), client, fxVerifyConfig); err == nil {
		t.Fatal("expected a non-nil error for an account that isn't EXACTLY configAccountSize, even though every field at its assumed offset happens to match")
	}
}

// TestVerifyVaultConfigOnChainRPCError covers a plain RPC failure
// (node unreachable/erroring) — must surface as an error, never panic.
func TestVerifyVaultConfigOnChainRPCError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"node unavailable"}}`)
	}))
	defer srv.Close()

	client := blockchain.NewRPCClient(srv.URL)
	_, err := verifyVaultConfigOnChain(context.Background(), client, fxVerifyConfig)
	if err == nil {
		t.Fatal("expected a non-nil error")
	}
	if !strings.Contains(err.Error(), "node unavailable") {
		t.Errorf("error = %v, want it to mention the RPC error message", err)
	}
}
