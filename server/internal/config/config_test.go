package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/mr-tron/base58"
)

// Fixed, deterministic 32-byte base58 pubkeys (encode(0x01*32), encode(0x02*32),
// ...) used across the config tests below — real Solana addresses have this
// exact shape, so any valid-looking distinct 32-byte value works as a
// fixture.
const (
	pubkeyCompliance       = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"
	pubkeyVault            = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"
	pubkeyPricing          = "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8"
	pubkeyTransferHook     = "GgBaCs3NCBuZN12kCJgAW63ydqohFkHEdfdEXBPzLHq"
	pubkeyRedemption       = "LbUiWL3xVV8hTFYBVdbTNrpDo41NKS6o3LHHuDzjfcY"
	pubkeySupplyController = "QWmroo4YnnMqYW3cnxWkFdaTxGD3P7vMSzwMHGbUzwF"
	pubkeyRWAMint          = "US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx"
	pubkeyQuoteMint        = "YMN9Qj5jPNp7j14VPcML1B6xGgcPWVZUGLFU3Mnyfaf"
	pubkeyAdmin            = "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN"
	clusterGenesis         = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
	supplyConfig           = "8sN3xz2XSXo7oJ6VfBJKF4G8VZ7pJZcFmqjWpZBAeZZ5"
	// vaultConfig is a distinct fixture pubkey from pubkeyVault
	// (the vault PROGRAM id) on purpose — the tests below assert these two
	// are never accidentally treated as interchangeable.
	vaultConfig = "3n1LDeUZm2q7NwiWWY6VkFpBEsWc3d2SNAhK6vAj9Fyc"
)

// env is a minimal valid config: every required chain.*/contract.* field set
// to a valid base58 pubkey, so a test can drop one and confirm it (and only it)
// makes Load fail.
func env() map[string]string {
	return map[string]string{
		"CHAIN_RPC_URL":                      "http://127.0.0.1:8899",
		"CHAIN_ID":                           "1",
		"CONTRACT_PROGRAM_COMPLIANCE":        pubkeyCompliance,
		"CONTRACT_PROGRAM_VAULT":             pubkeyVault,
		"CONTRACT_PROGRAM_PRICING":           pubkeyPricing,
		"CONTRACT_PROGRAM_TRANSFER_HOOK":     pubkeyTransferHook,
		"CONTRACT_PROGRAM_REDEMPTION":        pubkeyRedemption,
		"CONTRACT_PROGRAM_SUPPLY_CONTROLLER": pubkeySupplyController,
		"CONTRACT_RWA_MINT":                  pubkeyRWAMint,
		"CONTRACT_RWA_DECIMALS":              "9",
		"CONTRACT_QUOTE_MINT":                pubkeyQuoteMint,
		"CHAIN_CLUSTER_GENESIS":              clusterGenesis,
		"CONTRACT_SUPPLY_CONFIG":             supplyConfig,
		"CONTRACT_VAULT_CONFIG":              vaultConfig,
	}
}

// prodEnv is a minimal production config that PASSES every fail-closed
// check, built on top of env(), so a test can drop or override one
// field and confirm it (and only it) makes Load fail.
func prodEnv() map[string]string {
	env := env()
	env["ENVIRONMENT"] = "production"
	env["KYC_WEBHOOK_HMAC_SECRET"] = "01234567890123456789012345678901" // 33 bytes
	env["ADMIN_PUBKEY"] = pubkeyAdmin
	env["JWT_SECRET"] = "jwt-secret-0000000000000000000000000000000"
	env["PROJECT_ID"] = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	// IPFS_API_URL defaults to a non-empty value, so production's "at least
	// one independent backup destination" requirement (see Load's
	// IPFSReplicationThreshold checks) always applies unless explicitly
	// opted out — a fixed path is enough here since config.Load never
	// touches the filesystem itself.
	env["IPFS_BACKUP_ARCHIVE_DIR"] = "./testdata/ipfs-archive"
	return env
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := LoadFromMap(env())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %q, want :8080", cfg.HTTPAddr)
	}
	if cfg.MongoURI != "mongodb://127.0.0.1:27017" {
		t.Errorf("MongoURI = %q", cfg.MongoURI)
	}
	if cfg.IdempotencyTTL != 24*time.Hour {
		t.Errorf("IdempotencyTTL = %v, want 24h", cfg.IdempotencyTTL)
	}
	if cfg.WalletChallengeTTL != 15*time.Minute {
		t.Errorf("WalletChallengeTTL = %v, want 15m", cfg.WalletChallengeTTL)
	}
}

func TestLoadOverrides(t *testing.T) {
	env := env()
	env["HTTP_ADDR"] = ":9090"
	env["MONGO_URI"] = "mongodb://mongo:27017"
	env["IDEMPOTENCY_TTL"] = "1h"
	env["WALLET_CHALLENGE_TTL"] = "5m"
	cfg, err := LoadFromMap(env)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTPAddr != ":9090" {
		t.Errorf("HTTPAddr = %q", cfg.HTTPAddr)
	}
	if cfg.MongoURI != "mongodb://mongo:27017" {
		t.Errorf("MongoURI = %q", cfg.MongoURI)
	}
	if cfg.IdempotencyTTL != time.Hour {
		t.Errorf("IdempotencyTTL = %v", cfg.IdempotencyTTL)
	}
	if cfg.WalletChallengeTTL != 5*time.Minute {
		t.Errorf("WalletChallengeTTL = %v", cfg.WalletChallengeTTL)
	}
}

func TestLoadDefaultsTrustNoProxies(t *testing.T) {
	cfg, err := LoadFromMap(env())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.TrustedProxies != nil {
		t.Errorf("TrustedProxies = %v, want nil by default (trust no proxies — see the field's doc comment)", cfg.TrustedProxies)
	}
}

func TestLoadTrustedProxies(t *testing.T) {
	env := env()
	env["TRUSTED_PROXIES"] = "10.0.0.1, 172.16.0.0/12"
	cfg, err := LoadFromMap(env)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := []string{"10.0.0.1", "172.16.0.0/12"}
	if len(cfg.TrustedProxies) != len(want) {
		t.Fatalf("TrustedProxies = %v, want %v", cfg.TrustedProxies, want)
	}
	for i, w := range want {
		if cfg.TrustedProxies[i] != w {
			t.Errorf("TrustedProxies[%d] = %q, want %q", i, cfg.TrustedProxies[i], w)
		}
	}
}

// TestLoadInvalid is a table-driven regression test: each case starts from a
// valid env() baseline and overrides exactly the field(s) under test,
// so a failure is attributable to that field rather than to the required
// chain.*/contract.* baseline being incomplete.
func TestLoadInvalid(t *testing.T) {
	tests := map[string]map[string]string{
		"bad idempotency ttl":  {"IDEMPOTENCY_TTL": "not-a-duration"},
		"bad environment":      {"ENVIRONMENT": "staging"},
		"bad persistence mode": {"PERSISTENCE_MODE": "redis"},
		"bad kyc provider":     {"KYC_PROVIDER": "jumio"},
		"sumsub missing app token": {"KYC_PROVIDER": "sumsub",
			"KYC_SUMSUB_SECRET_KEY": "s", "KYC_SUMSUB_WEBHOOK_SECRET": "w"},
		"onfido missing workflow": {"KYC_PROVIDER": "onfido",
			"KYC_ONFIDO_API_TOKEN": "t", "KYC_ONFIDO_WEBHOOK_TOKEN": "w"},
		"onfido bad region": {"KYC_PROVIDER": "onfido", "KYC_ONFIDO_API_TOKEN": "t",
			"KYC_ONFIDO_WEBHOOK_TOKEN": "w", "KYC_ONFIDO_WORKFLOW_ID": "wf", "KYC_ONFIDO_REGION": "antarctica"},
	}
	for name, overrides := range tests {
		t.Run(name, func(t *testing.T) {
			env := env()
			for k, v := range overrides {
				env[k] = v
			}
			if _, err := LoadFromMap(env); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
}

// TestLoadDefaultsAreDevelopment pins the safe-for-local-dev defaults: no
// ENVIRONMENT/PERSISTENCE_MODE set at all must not accidentally trip the
// production-only checks below.
func TestLoadDefaultsAreDevelopment(t *testing.T) {
	cfg, err := LoadFromMap(env())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Environment != EnvDevelopment {
		t.Errorf("Environment = %q, want %q", cfg.Environment, EnvDevelopment)
	}
	if cfg.PersistenceMode != "mongo" {
		t.Errorf("PersistenceMode = %q, want mongo", cfg.PersistenceMode)
	}
}

// TestLoadDevelopmentAllowsEmptyWebhookSecret documents the intended
// non-production behavior: an unset secret is allowed (the feature is
// disabled by cmd/platform's buildApp, not by config.Load).
func TestLoadDevelopmentAllowsEmptyWebhookSecret(t *testing.T) {
	env := env()
	env["ENVIRONMENT"] = "development"
	if _, err := LoadFromMap(env); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
}

// TestLoadRejectsWeakWebhookSecretAnyEnvironment: the entropy floor
// applies whenever a secret is configured at all, not just in production —
// a placeholder like "changeme" should never silently pass.
func TestLoadRejectsWeakWebhookSecretAnyEnvironment(t *testing.T) {
	env := env()
	env["KYC_WEBHOOK_HMAC_SECRET"] = "too-short"
	if _, err := LoadFromMap(env); err == nil {
		t.Fatal("expected error for a below-minimum-length webhook secret")
	}
}

// TestLoadProductionRequiresWebhookSecret checks that starting the
// production configuration with an empty secret fails at startup.
func TestLoadProductionRequiresWebhookSecret(t *testing.T) {
	env := prodEnv()
	delete(env, "KYC_WEBHOOK_HMAC_SECRET")
	if _, err := LoadFromMap(env); err == nil {
		t.Fatal("expected production startup to fail with no KYC_WEBHOOK_HMAC_SECRET configured")
	}
}

// TestLoadProductionAcceptsStrongWebhookSecret is the positive counterpart:
// production with a secret meeting the documented minimum must start.
func TestLoadProductionAcceptsStrongWebhookSecret(t *testing.T) {
	if _, err := LoadFromMap(prodEnv()); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
}

// TestLoadProductionSumsubProvider: with a real provider active, the generic
// KYC_WEBHOOK_HMAC_SECRET is unused, so production must NOT require it —
// but it MUST require that provider's own webhook secret to meet the
// strength floor.
func TestLoadProductionSumsubProvider(t *testing.T) {
	env := prodEnv()
	delete(env, "KYC_WEBHOOK_HMAC_SECRET") // not needed when a provider is configured
	env["KYC_PROVIDER"] = "sumsub"
	env["KYC_SUMSUB_APP_TOKEN"] = "app-token"
	env["KYC_SUMSUB_SECRET_KEY"] = "secret-key"
	// too-short webhook secret must fail
	env["KYC_SUMSUB_WEBHOOK_SECRET"] = "short"
	if _, err := LoadFromMap(env); err == nil {
		t.Fatal("expected failure for a weak Sumsub webhook secret in production")
	}
	// a strong one passes with no generic secret present
	env["KYC_SUMSUB_WEBHOOK_SECRET"] = "01234567890123456789012345678901234"
	cfg, err := LoadFromMap(env)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.KYCProvider != "sumsub" {
		t.Fatalf("KYCProvider = %q, want sumsub", cfg.KYCProvider)
	}
}

// TestLoadProductionRequiresAdminAuth is the admin-auth regression test:
// admin routes authenticate a wallet-signature JWT, so production requires a
// configured admin wallet address AND a JWT signing secret; either missing,
// or a malformed admin pubkey, is a startup failure.
func TestLoadProductionRequiresAdminAuth(t *testing.T) {
	env := prodEnv()
	delete(env, "ADMIN_PUBKEY")
	if _, err := LoadFromMap(env); err == nil {
		t.Fatal("expected production startup to fail without ADMIN_PUBKEY")
	}
	env = prodEnv()
	delete(env, "JWT_SECRET")
	if _, err := LoadFromMap(env); err == nil {
		t.Fatal("expected production startup to fail without JWT_SECRET")
	}
	env = prodEnv()
	env["ADMIN_PUBKEY"] = "not-valid-base58-0OIl"
	if _, err := LoadFromMap(env); err == nil {
		t.Fatal("expected production startup to fail with a malformed ADMIN_PUBKEY")
	}
}

// TestLoadProductionRejectsMemoryPersistence: production must never
// silently run on volatile in-memory repositories.
func TestLoadProductionRejectsMemoryPersistence(t *testing.T) {
	env := prodEnv()
	env["PERSISTENCE_MODE"] = "memory"
	if _, err := LoadFromMap(env); err == nil {
		t.Fatal("expected production startup to fail with PERSISTENCE_MODE=memory")
	}
}

// TestLoadProductionRequiresProjectID: production must not start without a
// pinned projectId — the gate that fixes which Asset Profile the deployment
// will accept has to be armed before any profile can be created.
func TestLoadProductionRequiresProjectID(t *testing.T) {
	env := prodEnv()
	delete(env, "PROJECT_ID")
	if _, err := LoadFromMap(env); err == nil {
		t.Fatal("expected production startup to fail with no PROJECT_ID set")
	}
}

// TestLoadRejectsMalformedProjectID: a non-UUID projectId is caught at load in
// any environment, not deferred to the first profile create.
func TestLoadRejectsMalformedProjectID(t *testing.T) {
	env := env()
	env["PROJECT_ID"] = "not-a-uuid"
	if _, err := LoadFromMap(env); err == nil {
		t.Fatal("expected load to reject a malformed PROJECT_ID")
	}
}

// TestLoadProductionRequiresIPFSBackupDestination: IPFS_API_URL defaults
// to a non-empty value, so
// production must refuse to start without at least one independent
// replication destination configured, rather than silently falling back to
// a single bare local Kubo node with no durable-publication tracking.
func TestLoadProductionRequiresIPFSBackupDestination(t *testing.T) {
	env := prodEnv()
	delete(env, "IPFS_BACKUP_ARCHIVE_DIR")
	if _, err := LoadFromMap(env); err == nil {
		t.Fatal("expected production startup to fail with IPFS_API_URL enabled but no backup destination configured")
	}
}

// TestLoadProductionRejectsReplicationThresholdOutOfRange covers both
// directions of "validate 1 <= threshold <= destination count."
func TestLoadProductionRejectsReplicationThresholdOutOfRange(t *testing.T) {
	tests := map[string]string{"zero": "0", "negative": "-1", "exceeds destination count": "2"}
	for name, threshold := range tests {
		t.Run(name, func(t *testing.T) {
			env := prodEnv() // exactly one backup destination configured
			env["IPFS_REPLICATION_THRESHOLD"] = threshold
			if _, err := LoadFromMap(env); err == nil {
				t.Fatalf("expected production startup to fail with IPFS_REPLICATION_THRESHOLD=%s and 1 configured backup", threshold)
			}
		})
	}
}

// TestLoadProductionAcceptsReplicationThresholdWithinRange is the positive
// case, including a second backup destination raising the valid ceiling.
func TestLoadProductionAcceptsReplicationThresholdWithinRange(t *testing.T) {
	env := prodEnv()
	env["IPFS_BACKUP_KUBO_URL"] = "http://backup-kubo:5001"
	env["IPFS_REPLICATION_THRESHOLD"] = "2"
	if _, err := LoadFromMap(env); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
}

// TestLoadDevelopmentAllowsMemoryPersistence: memory is a supported,
// explicit opt-in outside production (local smoke tests, CI).
func TestLoadDevelopmentAllowsMemoryPersistence(t *testing.T) {
	env := env()
	env["PERSISTENCE_MODE"] = "memory"
	if _, err := LoadFromMap(env); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
}

// TestLoadDefaultMetricsAddrIsLoopback: metrics must not listen on all
// interfaces by default.
func TestLoadDefaultMetricsAddrIsLoopback(t *testing.T) {
	cfg, err := LoadFromMap(env())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.MetricsAddr != "127.0.0.1:9090" {
		t.Errorf("MetricsAddr = %q, want 127.0.0.1:9090", cfg.MetricsAddr)
	}
}

// TestLoadDefaultHTTPHardening: every listener gets non-zero timeouts and a
// header-size cap out of the box.
func TestLoadDefaultHTTPHardening(t *testing.T) {
	cfg, err := LoadFromMap(env())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTPReadHeaderTimeout <= 0 {
		t.Error("HTTPReadHeaderTimeout must default to a positive duration")
	}
	if cfg.HTTPReadTimeout <= 0 {
		t.Error("HTTPReadTimeout must default to a positive duration")
	}
	if cfg.HTTPWriteTimeout <= 0 {
		t.Error("HTTPWriteTimeout must default to a positive duration")
	}
	if cfg.HTTPIdleTimeout <= 0 {
		t.Error("HTTPIdleTimeout must default to a positive duration")
	}
	if cfg.HTTPMaxHeaderBytes <= 0 {
		t.Error("HTTPMaxHeaderBytes must default to a positive value")
	}
}

// --- Production config hardening ---

// TestLoadProductionRejectsTrivialSecrets is a table-driven regression test:
// every known placeholder, and every too-short value, must be rejected for
// the JWT signing secret.
func TestLoadProductionRejectsTrivialSecrets(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"single char a", "a"},
		{"single char b", "b"},
		{"changeme", "changeme"},
		{"CHANGEME uppercase", "CHANGEME"},
		{"password", "password"},
		{"admin literal", "admin"},
		{"31 bytes (one short)", strings.Repeat("x", 31)},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run("jwt/"+tt.name, func(t *testing.T) {
			env := prodEnv()
			env["JWT_SECRET"] = tt.value
			if _, err := LoadFromMap(env); err == nil {
				t.Fatalf("expected production startup to reject JWT_SECRET=%q", tt.value)
			}
		})
	}
}

// TestLoadProductionAcceptsStrongSecrets is the positive counterpart,
// already implicitly covered by prodEnv()-based tests, made explicit here.
func TestLoadProductionAcceptsStrongSecrets(t *testing.T) {
	if _, err := LoadFromMap(prodEnv()); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
}

// TestLoadProductionRejectsNonPositiveDurationsAndLimits is a table-driven
// test that positive lower/upper bounds are enforced for every security
// duration and body/header limit. Each entry sets exactly one
// previously-unbounded knob to a disabling/invalid value on top of an
// otherwise-valid prodEnv() and expects Load to reject it.
func TestLoadProductionRejectsNonPositiveDurationsAndLimits(t *testing.T) {
	tests := map[string]string{
		"IDEMPOTENCY_TTL":          "0",
		"WALLET_CHALLENGE_TTL":     "-1s",
		"WALLET_SESSION_TTL":       "0",
		"JWT_TTL":                  "0",
		"HTTP_READ_HEADER_TIMEOUT": "0",
		"HTTP_READ_TIMEOUT":        "0",
		"HTTP_WRITE_TIMEOUT":       "0",
		"HTTP_IDLE_TIMEOUT":        "0",
		"PENDING_REDEMPTION_SLA":   "0",
		"FUNDED_CLAIM_FAILURE_SLA": "0",
		"HTTP_MAX_HEADER_BYTES":    "0",
	}
	for key, value := range tests {
		t.Run(key, func(t *testing.T) {
			env := prodEnv()
			env[key] = value
			if _, err := LoadFromMap(env); err == nil {
				t.Fatalf("expected production startup to reject %s=%q", key, value)
			}
		})
	}
}

// TestLoadProductionDisabledControlsRequireExplicitOverride covers the two
// genuinely "disabled" controls (body limit, rate limit): rejected by
// default, accepted only with their narrowly-named PRODUCTION_ALLOW_*
// override set.
func TestLoadProductionDisabledControlsRequireExplicitOverride(t *testing.T) {
	tests := []struct {
		name        string
		disableKey  string
		disableVal  string
		overrideKey string
	}{
		{"request body limit", "MAX_REQUEST_BODY_BYTES", "0", "PRODUCTION_ALLOW_UNBOUNDED_REQUEST_BODY"},
		{"rate limit", "RATE_LIMIT_RPS", "0", "PRODUCTION_ALLOW_DISABLED_RATE_LIMIT"},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/rejected without override", func(t *testing.T) {
			env := prodEnv()
			env[tt.disableKey] = tt.disableVal
			if _, err := LoadFromMap(env); err == nil {
				t.Fatalf("expected production startup to reject %s=%s without an override", tt.disableKey, tt.disableVal)
			}
		})
		t.Run(tt.name+"/accepted with override", func(t *testing.T) {
			env := prodEnv()
			env[tt.disableKey] = tt.disableVal
			env[tt.overrideKey] = "true"
			if _, err := LoadFromMap(env); err != nil {
				t.Fatalf("expected the explicit override to be accepted: %v", err)
			}
		})
	}
}

// TestLoadProductionRejectsZeroBurstWhenRateLimitEnabled is the specific
// cross-field constraint: a positive RPS with a non-positive burst is
// still a broken (self-inflicted-DoS-prone) configuration.
func TestLoadProductionRejectsZeroBurstWhenRateLimitEnabled(t *testing.T) {
	env := prodEnv()
	env["RATE_LIMIT_RPS"] = "50"
	env["RATE_LIMIT_BURST"] = "0"
	if _, err := LoadFromMap(env); err == nil {
		t.Fatal("expected production startup to reject RATE_LIMIT_BURST=0 with RATE_LIMIT_RPS enabled")
	}
}

// TestLoadProductionRejectsOverflowAndGarbageDurations proves malformed
// duration/int inputs (not just semantically zero/negative ones) are
// caught by the underlying parse step for every newly-bounded field, not
// only the pre-existing ones already covered by TestLoadInvalid.
func TestLoadProductionRejectsOverflowAndGarbageDurations(t *testing.T) {
	tests := map[string]string{
		"HTTP_MAX_HEADER_BYTES": "99999999999999999999999999", // overflows int64
		"WALLET_SESSION_TTL":    "not-a-duration",
	}
	for key, value := range tests {
		t.Run(key, func(t *testing.T) {
			env := prodEnv()
			env[key] = value
			if _, err := LoadFromMap(env); err == nil {
				t.Fatalf("expected production startup to reject %s=%q", key, value)
			}
		})
	}
}

// TestLoadValidConfig is the positive case: every required chain.*/contract.*
// field set to a valid base58 pubkey parses cleanly and flows through to the
// resolved Config unchanged.
func TestLoadValidConfig(t *testing.T) {
	env := env()
	env["CHAIN_START_SLOT"] = "1000"
	env["ADMIN_PUBKEY"] = pubkeyAdmin
	env["CONTRACT_QUOTE_DECIMALS"] = "6"
	cfg, err := LoadFromMap(env)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Commitment != "finalized" {
		t.Errorf("Commitment = %q, want the default %q", cfg.Commitment, "finalized")
	}
	if cfg.RPCURL != "http://127.0.0.1:8899" {
		t.Errorf("RPCURL = %q", cfg.RPCURL)
	}
	if cfg.ChainID != 1 {
		t.Errorf("ChainID = %d, want 1", cfg.ChainID)
	}
	if cfg.StartSlot != 1000 {
		t.Errorf("StartSlot = %d, want 1000", cfg.StartSlot)
	}
	if cfg.ProgramCompliance != pubkeyCompliance {
		t.Errorf("ProgramCompliance = %q", cfg.ProgramCompliance)
	}
	if cfg.ProgramSupplyController != pubkeySupplyController {
		t.Errorf("ProgramSupplyController = %q", cfg.ProgramSupplyController)
	}
	if cfg.RWAMint != pubkeyRWAMint || cfg.QuoteMint != pubkeyQuoteMint {
		t.Errorf("RWAMint/QuoteMint = %q/%q", cfg.RWAMint, cfg.QuoteMint)
	}
	if cfg.AdminPubkey != pubkeyAdmin {
		t.Errorf("AdminPubkey = %q", cfg.AdminPubkey)
	}
	if cfg.QuoteDecimals != 6 {
		t.Errorf("QuoteDecimals = %d, want 6", cfg.QuoteDecimals)
	}
	if cfg.RWADecimals != 9 {
		t.Errorf("RWADecimals = %d, want 9", cfg.RWADecimals)
	}
	if want := int64(14 * 24 * 60 * 60); cfg.RedemptionTimeout != want {
		t.Errorf("RedemptionTimeout = %d, want the default %d (14 days)", cfg.RedemptionTimeout, want)
	}
	if cfg.ClusterGenesis != clusterGenesis {
		t.Errorf("ClusterGenesis = %q, want %q", cfg.ClusterGenesis, clusterGenesis)
	}
	if cfg.SupplyConfig != supplyConfig {
		t.Errorf("SupplyConfig = %q, want %q", cfg.SupplyConfig, supplyConfig)
	}
	if cfg.VaultConfig != vaultConfig {
		t.Errorf("VaultConfig = %q, want %q", cfg.VaultConfig, vaultConfig)
	}
	// The vault-config PDA and the vault PROGRAM id are two distinct
	// fields fed from two distinct env keys — this was exactly the
	// distinction collapsing to one value downstream in cmd/platform, so
	// pin here that config.Load itself keeps them separate.
	if cfg.VaultConfig == cfg.ProgramVault {
		t.Errorf("VaultConfig must not equal ProgramVault (the vault program id) — got %q for both", cfg.VaultConfig)
	}
	if want := 5 * time.Minute; cfg.MaxCheckpointAge != want {
		t.Errorf("MaxCheckpointAge = %s, want the default %s", cfg.MaxCheckpointAge, want)
	}
}

// TestLoadMaxCheckpointAgeOverride covers chain.max_checkpoint_age: an
// explicit override flows through.
func TestLoadMaxCheckpointAgeOverride(t *testing.T) {
	env := env()
	env["CHAIN_MAX_CHECKPOINT_AGE"] = "90s"
	cfg, err := LoadFromMap(env)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if want := 90 * time.Second; cfg.MaxCheckpointAge != want {
		t.Errorf("MaxCheckpointAge = %s, want %s", cfg.MaxCheckpointAge, want)
	}
}

// TestLoadRedemptionTimeoutOverrideAndValidation covers
// contract.redemption_timeout: an explicit in-bound override flows through,
// and a value outside [1 day, 365 days] — the same bound
// solana/programs/rwa-redemption/src/lib.rs's `initialize` enforces
// on-chain — is rejected; before this bound, only "> 0" was
// checked, so an obviously wrong value like an hour or a decade would only
// surface as silently wrong claimable/timeout dates, never a startup
// failure.
func TestLoadRedemptionTimeoutOverrideAndValidation(t *testing.T) {
	t.Run("explicit override", func(t *testing.T) {
		env := env()
		env["CONTRACT_REDEMPTION_TIMEOUT"] = "172800" // 2 days -- in bounds
		cfg, err := LoadFromMap(env)
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.RedemptionTimeout != 172800 {
			t.Errorf("RedemptionTimeout = %d, want 172800", cfg.RedemptionTimeout)
		}
	})
	t.Run("exact bounds are accepted", func(t *testing.T) {
		for _, v := range []string{"86400", "31536000"} { // 1 day, 365 days
			env := env()
			env["CONTRACT_REDEMPTION_TIMEOUT"] = v
			if _, err := LoadFromMap(env); err != nil {
				t.Errorf("Load() with CONTRACT_REDEMPTION_TIMEOUT=%s: %v", v, err)
			}
		}
	})
	t.Run("zero is rejected", func(t *testing.T) {
		env := env()
		env["CONTRACT_REDEMPTION_TIMEOUT"] = "0"
		if _, err := LoadFromMap(env); err == nil {
			t.Fatal("expected Load() to reject CONTRACT_REDEMPTION_TIMEOUT=0")
		}
	})
	t.Run("negative is rejected", func(t *testing.T) {
		env := env()
		env["CONTRACT_REDEMPTION_TIMEOUT"] = "-1"
		if _, err := LoadFromMap(env); err == nil {
			t.Fatal("expected Load() to reject a negative CONTRACT_REDEMPTION_TIMEOUT")
		}
	})
	t.Run("below one day is rejected", func(t *testing.T) {
		env := env()
		env["CONTRACT_REDEMPTION_TIMEOUT"] = "3600" // 1 hour
		if _, err := LoadFromMap(env); err == nil {
			t.Fatal("expected Load() to reject a CONTRACT_REDEMPTION_TIMEOUT below 1 day")
		}
	})
	t.Run("above 365 days is rejected", func(t *testing.T) {
		env := env()
		env["CONTRACT_REDEMPTION_TIMEOUT"] = "31536001" // 365 days + 1 second
		if _, err := LoadFromMap(env); err == nil {
			t.Fatal("expected Load() to reject a CONTRACT_REDEMPTION_TIMEOUT above 365 days")
		}
	})
}

// TestLoadRWADecimalsRequiredAndBounded covers contract.rwa_decimals:
// required (unlike quote_decimals, which may default to 0 — see
// SeedProject's doc comment on why this one can't), 0 is itself a
// valid explicit value, and the [0,36] sanity bound (mirroring the Asset
// Profile's tokenDecimals) is enforced.
func TestLoadRWADecimalsRequiredAndBounded(t *testing.T) {
	t.Run("missing is rejected", func(t *testing.T) {
		env := env()
		delete(env, "CONTRACT_RWA_DECIMALS")
		if _, err := LoadFromMap(env); err == nil {
			t.Fatal("expected Load() to reject contract.rwa_decimals unset")
		}
	})
	t.Run("explicit zero is accepted", func(t *testing.T) {
		env := env()
		env["CONTRACT_RWA_DECIMALS"] = "0"
		cfg, err := LoadFromMap(env)
		if err != nil {
			t.Fatalf("Load() error = %v (explicit 0 must be a valid decimals value)", err)
		}
		if cfg.RWADecimals != 0 {
			t.Errorf("RWADecimals = %d, want 0", cfg.RWADecimals)
		}
	})
	t.Run("above 36 is rejected", func(t *testing.T) {
		env := env()
		env["CONTRACT_RWA_DECIMALS"] = "37"
		if _, err := LoadFromMap(env); err == nil {
			t.Fatal("expected Load() to reject CONTRACT_RWA_DECIMALS=37 (above the [0,36] bound)")
		}
	})
}

// TestLoadMissingProgramIDFails: startup requires all six program
// addresses plus the two mint addresses — dropping any one of them must fail
// startup rather than silently leaving that field unconfigured.
func TestLoadMissingProgramIDFails(t *testing.T) {
	missing := []string{
		"CONTRACT_PROGRAM_COMPLIANCE", "CONTRACT_PROGRAM_VAULT", "CONTRACT_PROGRAM_PRICING",
		"CONTRACT_PROGRAM_TRANSFER_HOOK", "CONTRACT_PROGRAM_REDEMPTION", "CONTRACT_PROGRAM_SUPPLY_CONTROLLER",
		// The mint-attestation domain inputs (see Config.ClusterGenesis's
		// doc comment) are required through the exact same
		// requiredPubkeys mechanism as the six program ids above.
		"CHAIN_CLUSTER_GENESIS", "CONTRACT_SUPPLY_CONFIG", "CONTRACT_VAULT_CONFIG",
		// The two mint addresses go through requiredPubkeys too, same as
		// the program ids and the mint-attestation inputs above.
		"CONTRACT_RWA_MINT", "CONTRACT_QUOTE_MINT",
	}
	for _, key := range missing {
		t.Run(key, func(t *testing.T) {
			env := env()
			delete(env, key)
			if _, err := LoadFromMap(env); err == nil {
				t.Fatalf("expected Load() to fail with %s unset", key)
			}
		})
	}
}

// TestLoadRejectsMalformedClusterGenesisOrSupplyConfig covers the
// base58-validation half (not just presence) of the mint-attestation domain
// inputs.
func TestLoadRejectsMalformedClusterGenesisOrSupplyConfig(t *testing.T) {
	t.Run("cluster_genesis", func(t *testing.T) {
		env := env()
		env["CHAIN_CLUSTER_GENESIS"] = "not-valid-base58-0OIl"
		if _, err := LoadFromMap(env); err == nil {
			t.Fatal("expected Load() to reject a malformed CHAIN_CLUSTER_GENESIS")
		}
	})
	t.Run("supply_config", func(t *testing.T) {
		env := env()
		env["CONTRACT_SUPPLY_CONFIG"] = "not-valid-base58-0OIl"
		if _, err := LoadFromMap(env); err == nil {
			t.Fatal("expected Load() to reject a malformed CONTRACT_SUPPLY_CONFIG")
		}
	})
	// vault_config: required + base58-validated exactly like
	// cluster_genesis/supply_config above.
	t.Run("vault_config", func(t *testing.T) {
		env := env()
		env["CONTRACT_VAULT_CONFIG"] = "not-valid-base58-0OIl"
		if _, err := LoadFromMap(env); err == nil {
			t.Fatal("expected Load() to reject a malformed CONTRACT_VAULT_CONFIG")
		}
	})
}

// TestLoadComplianceKeyIsOptional covers security.compliance_key: it is
// NOT required (compliance status writes are simply disabled when unset —
// see Config.ComplianceKey's doc comment).
func TestLoadComplianceKeyIsOptional(t *testing.T) {
	t.Run("unset is fine", func(t *testing.T) {
		env := env()
		if _, ok := env["COMPLIANCE_KEY"]; ok {
			t.Fatal("env() must not set COMPLIANCE_KEY by default")
		}
		cfg, err := LoadFromMap(env)
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.ComplianceKey != "" {
			t.Errorf("ComplianceKey = %q, want empty", cfg.ComplianceKey)
		}
	})
	t.Run("explicit value flows through", func(t *testing.T) {
		env := env()
		env["COMPLIANCE_KEY"] = "some-base58-or-path"
		cfg, err := LoadFromMap(env)
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.ComplianceKey != "some-base58-or-path" {
			t.Errorf("ComplianceKey = %q, want some-base58-or-path", cfg.ComplianceKey)
		}
	})
}

// TestLoadQuoteDecimalsBounds pins contract.quote_decimals' current
// bound: only the byte-width check (0-255, applied to every getUint64-parsed
// field) is enforced — unlike rwa_decimals, there is no [0,36] sanity
// ceiling for quote_decimals (rwa_decimals feeds Project.TokenDecimals
// directly and must stay in the same sane range the Asset Profile enforces;
// quote_decimals is just carried through for display scaling — see
// CONTRACT_RWA_DECIMALS's required-and-bounded doc comment). This pins the
// current, intentionally asymmetric behavior; it is not asserting 255 is a
// sensible decimals value.
func TestLoadQuoteDecimalsBounds(t *testing.T) {
	t.Run("255 (max byte) is accepted", func(t *testing.T) {
		env := env()
		env["CONTRACT_QUOTE_DECIMALS"] = "255"
		cfg, err := LoadFromMap(env)
		if err != nil {
			t.Fatalf("Load() error = %v (255 must fit the byte-width check even though it's far outside [0,36])", err)
		}
		if cfg.QuoteDecimals != 255 {
			t.Errorf("QuoteDecimals = %d, want 255", cfg.QuoteDecimals)
		}
	})
	t.Run("256 overflows the byte and is rejected", func(t *testing.T) {
		env := env()
		env["CONTRACT_QUOTE_DECIMALS"] = "256"
		if _, err := LoadFromMap(env); err == nil {
			t.Fatal("expected Load() to reject CONTRACT_QUOTE_DECIMALS=256 (does not fit in a byte)")
		}
	})
}

// TestLoadRWADecimalsRejectsByteOverflow covers the byte-width check
// for contract.rwa_decimals, distinct from the [0,36] semantic bound already
// covered by TestLoadRWADecimalsRequiredAndBounded's "above 36" case —
// 256 fails at the getUint64 byte-fit check before the [0,36] check is even
// reached.
func TestLoadRWADecimalsRejectsByteOverflow(t *testing.T) {
	env := env()
	env["CONTRACT_RWA_DECIMALS"] = "256"
	if _, err := LoadFromMap(env); err == nil {
		t.Fatal("expected Load() to reject CONTRACT_RWA_DECIMALS=256 (does not fit in a byte)")
	}
}

// TestLoadRejectsMalformedAdminPubkey covers the base58-validation
// half of security.admin_pubkey. It is optional in non-production configs
// (see TestLoadValidConfig, which never sets it), but whenever it IS
// set it must still be a well-formed 32-byte base58 pubkey, same as every
// other contract.* pubkey field.
func TestLoadRejectsMalformedAdminPubkey(t *testing.T) {
	env := env()
	env["ADMIN_PUBKEY"] = "not-valid-base58-0OIl"
	if _, err := LoadFromMap(env); err == nil {
		t.Fatal("expected Load() to reject a malformed ADMIN_PUBKEY")
	}
}

// TestLoadRejectsMalformedPubkey: a program ID that isn't valid base58
// (or doesn't decode to 32 bytes) must be caught at startup, not at first
// on-chain call.
func TestLoadRejectsMalformedPubkey(t *testing.T) {
	env := env()
	env["CONTRACT_PROGRAM_VAULT"] = "not-valid-base58-0OIl"
	if _, err := LoadFromMap(env); err == nil {
		t.Fatal("expected Load() to reject a malformed CONTRACT_PROGRAM_VAULT")
	}
}

// TestLoadRequiresRPCURLAndPositiveChainID covers the two non-pubkey
// required fields.
func TestLoadRequiresRPCURLAndPositiveChainID(t *testing.T) {
	t.Run("missing rpc url", func(t *testing.T) {
		env := env()
		delete(env, "CHAIN_RPC_URL")
		if _, err := LoadFromMap(env); err == nil {
			t.Fatal("expected Load() to fail with CHAIN_RPC_URL unset")
		}
	})
	t.Run("non-positive chain id", func(t *testing.T) {
		env := env()
		env["CHAIN_ID"] = "0"
		if _, err := LoadFromMap(env); err == nil {
			t.Fatal("expected Load() to fail with CHAIN_ID=0")
		}
	})
}

// TestLoadCommitmentValidation covers chain.commitment validation:
// it must be one of the three real Solana commitment levels, in every
// environment, and production additionally requires "finalized" unless the
// narrowly-named PRODUCTION_ALLOW_WEAK_COMMITMENT override is set —
// the indexer has zero reorg handling, so correctness rests entirely on
// finalized (see indexer.go's doc comment).
func TestLoadCommitmentValidation(t *testing.T) {
	t.Run("unrecognized value is rejected in development", func(t *testing.T) {
		env := env()
		env["CHAIN_COMMITMENT"] = "bogus"
		if _, err := LoadFromMap(env); err == nil {
			t.Fatal("expected Load() to reject an unrecognized chain.commitment")
		}
	})
	t.Run("processed and confirmed are valid in development", func(t *testing.T) {
		for _, c := range []string{"processed", "confirmed", "finalized"} {
			env := env()
			env["CHAIN_COMMITMENT"] = c
			if _, err := LoadFromMap(env); err != nil {
				t.Errorf("Load() with chain.commitment=%q: %v", c, err)
			}
		}
	})
	t.Run("weaker than finalized rejected in production", func(t *testing.T) {
		env := prodEnv()
		env["CHAIN_COMMITMENT"] = "confirmed"
		if _, err := LoadFromMap(env); err == nil {
			t.Fatal("expected production Load() to reject chain.commitment=confirmed")
		}
	})
	t.Run("finalized accepted in production", func(t *testing.T) {
		env := prodEnv()
		env["CHAIN_COMMITMENT"] = "finalized"
		if _, err := LoadFromMap(env); err != nil {
			t.Fatalf("Load() error = %v", err)
		}
	})
	t.Run("override permits a weaker commitment in production", func(t *testing.T) {
		env := prodEnv()
		env["CHAIN_COMMITMENT"] = "processed"
		env["PRODUCTION_ALLOW_WEAK_COMMITMENT"] = "true"
		if _, err := LoadFromMap(env); err != nil {
			t.Fatalf("Load() error = %v, want the override to permit chain.commitment=processed", err)
		}
	})
}

// TestLoadProductionRequiresHTTPSRPCURL covers the production
// HTTPS-RPC requirement: a non-loopback Solana RPC URL must use https in
// production (a plaintext endpoint is MITM-injectable, and the indexer
// trusts every RPC response
// wholesale), while loopback hosts remain exempt for local testing.
func TestLoadProductionRequiresHTTPSRPCURL(t *testing.T) {
	t.Run("plaintext non-loopback rpc_url rejected", func(t *testing.T) {
		env := prodEnv()
		env["CHAIN_RPC_URL"] = "http://rpc.example.com"
		if _, err := LoadFromMap(env); err == nil {
			t.Fatal("expected production Load() to reject a plaintext non-loopback chain.rpc_url")
		}
	})
	t.Run("https non-loopback rpc_url accepted", func(t *testing.T) {
		env := prodEnv()
		env["CHAIN_RPC_URL"] = "https://rpc.example.com"
		if _, err := LoadFromMap(env); err != nil {
			t.Fatalf("Load() error = %v", err)
		}
	})
	t.Run("plaintext loopback rpc_url accepted", func(t *testing.T) {
		env := prodEnv() // env's default CHAIN_RPC_URL is the loopback http://127.0.0.1:8899
		if _, err := LoadFromMap(env); err != nil {
			t.Fatalf("Load() error = %v, want a loopback RPC URL exempt from the https requirement", err)
		}
	})
}

// TestLoadProductionCompliancePlaintextKeyGuard covers the production
// plaintext-key guard: the compliance key has no keys.Provider
// abstraction to route through — only an inline base58 secret or a
// plaintext keypair-file path
// are supported (see cmd/platform's loadComplianceKey). Production
// must refuse the inline form — keeping key material directly in this
// plaintext config — unless the operator explicitly opts in via
// PRODUCTION_ALLOW_PLAINTEXT_COMPLIANCE_KEY.
func TestLoadProductionCompliancePlaintextKeyGuard(t *testing.T) {
	inlineKey := func(t *testing.T) string {
		t.Helper()
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return base58.Encode(priv)
	}

	t.Run("inline key rejected in production without override", func(t *testing.T) {
		env := prodEnv()
		env["COMPLIANCE_KEY"] = inlineKey(t)
		if _, err := LoadFromMap(env); err == nil {
			t.Fatal("expected production Load() to reject an inline base58 security.compliance_key")
		}
	})
	t.Run("inline key accepted in production with override", func(t *testing.T) {
		env := prodEnv()
		env["COMPLIANCE_KEY"] = inlineKey(t)
		env["PRODUCTION_ALLOW_PLAINTEXT_COMPLIANCE_KEY"] = "true"
		cfg, err := LoadFromMap(env)
		if err != nil {
			t.Fatalf("Load() error = %v, want the override to permit an inline security.compliance_key", err)
		}
		if !cfg.AllowPlaintextComplianceKey {
			t.Error("AllowPlaintextComplianceKey = false, want true")
		}
	})
	t.Run("keypair file path accepted in production without override", func(t *testing.T) {
		env := prodEnv()
		env["COMPLIANCE_KEY"] = "/etc/rwa-platform/solana-compliance-keypair.json"
		if _, err := LoadFromMap(env); err != nil {
			t.Fatalf("Load() error = %v, want a keypair-file path accepted without an override", err)
		}
	})
	t.Run("unset key accepted in production", func(t *testing.T) {
		env := prodEnv()
		if _, err := LoadFromMap(env); err != nil {
			t.Fatalf("Load() error = %v, want an unset security.compliance_key (compliance writes disabled) accepted", err)
		}
	})
	t.Run("inline key accepted in development without override", func(t *testing.T) {
		env := env()
		env["COMPLIANCE_KEY"] = inlineKey(t)
		if _, err := LoadFromMap(env); err != nil {
			t.Fatalf("Load() error = %v, want development unaffected by the production-only guard", err)
		}
	})
}

// TestIsInlineSecretKey pins isInlineSecretKey's "try base58
// first" resolution directly, mirroring cmd/platform's
// loadComplianceKey.
func TestIsInlineSecretKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !isInlineSecretKey(base58.Encode(priv)) {
		t.Error("a valid base58-encoded 64-byte secret key must be reported as inline")
	}
	for _, s := range []string{
		"", "/etc/rwa-platform/solana-compliance-keypair.json", "not-valid-base58-0OIl",
		base58.Encode([]byte("too-short-to-be-a-secret-key")),
	} {
		if isInlineSecretKey(s) {
			t.Errorf("isInlineSecretKey(%q) = true, want false", s)
		}
	}
}

// TestLoadFileRejectsPublicRPCURL covers the removed solana.public_rpc_url
// no longer exists in fileSchema, so a YAML config still setting it (a stale
// operator config from before the field was removed) must fail startup via
// KnownFields(true) rather than silently doing nothing — the same guard
// TestLoadFileRejectsUnknownKey exercises for an ordinary typo. (LoadFromMap
// has no equivalent "unknown key" concept — env-map keys the code no longer
// reads are always silently unused, by design — so this must go through
// LoadFile.)
func TestLoadFileRejectsPublicRPCURL(t *testing.T) {
	const yaml = `
solana:
  public_rpc_url: "https://rpc.example.com"
`
	if _, err := LoadFile(writeConfig(t, yaml)); err == nil {
		t.Fatal("expected an error for the removed solana.public_rpc_url key (the browser RPC URL is build-time only)")
	}
}

// TestLoadCORSAllowedOrigins covers the parse: a comma-separated list becomes
// discrete origins, with surrounding whitespace and empty entries dropped.
func TestLoadCORSAllowedOrigins(t *testing.T) {
	env := env()
	env["CORS_ALLOWED_ORIGINS"] = " http://localhost:5137 , https://investor.example ,, "
	cfg, err := LoadFromMap(env)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"http://localhost:5137", "https://investor.example"}
	if len(cfg.CORSAllowedOrigins) != len(want) {
		t.Fatalf("CORSAllowedOrigins = %v, want %v", cfg.CORSAllowedOrigins, want)
	}
	for i, w := range want {
		if cfg.CORSAllowedOrigins[i] != w {
			t.Errorf("origin %d = %q, want %q", i, cfg.CORSAllowedOrigins[i], w)
		}
	}
}

// TestLoadCORSDefaultsToDisabled: the default must be no cross-origin access at
// all. A deployment serving only the embedded (same-origin) console needs none,
// and defaulting to anything permissive would hand every such deployment a
// cross-origin surface it never asked for.
func TestLoadCORSDefaultsToDisabled(t *testing.T) {
	cfg, err := LoadFromMap(env())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.CORSAllowedOrigins) != 0 {
		t.Errorf("CORSAllowedOrigins = %v, want empty by default", cfg.CORSAllowedOrigins)
	}
}

// TestLoadRejectsBadCORSOrigins is the fail-closed half, enforced in EVERY
// environment rather than production only.
//
// "*" is the load-bearing case: this API accepts an Authorization bearer, so a
// wildcard origin would let any page on the internet drive an authenticated
// admin session out of a victim's browser. The malformed cases matter for a
// duller reason — a browser's Origin header is exactly scheme+host+port, so a
// trailing slash or a missing scheme silently never matches, and the operator
// sees "CORS is broken" with nothing explaining why.
func TestLoadRejectsBadCORSOrigins(t *testing.T) {
	for name, value := range map[string]string{
		"wildcard":              "*",
		"wildcard among others": "http://localhost:5137,*",
		"trailing slash":        "http://localhost:5137/",
		"missing scheme":        "localhost:5137",
		"bare host":             "investor.example",
	} {
		t.Run(name, func(t *testing.T) {
			env := env()
			env["CORS_ALLOWED_ORIGINS"] = value
			if _, err := LoadFromMap(env); err == nil {
				t.Fatalf("expected load to reject CORS_ALLOWED_ORIGINS=%q", value)
			}
		})
	}
}
