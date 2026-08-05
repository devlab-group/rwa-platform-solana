package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeConfig writes contents to a temp YAML file and returns its path.
func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

// chainYAML is the YAML `chain:` block every test fixture needs: the RPC
// endpoint, chain id, and cluster genesis hash — the counterpart of
// config_test.go's env() chain.* fields.
var chainYAML = fmt.Sprintf(`chain:
  rpc_url: "http://127.0.0.1:8899"
  chain_id: 1
  cluster_genesis: %q
`, clusterGenesis)

// contractYAML returns a complete YAML `contract:` block: the six program
// ids, the two mints + decimals, and the two mint-attestation domain PDAs,
// reusing the same fixture constants as config_test.go's env(). projectID is
// included as the block's first field when non-empty (empty matches env()'s
// own default of PROJECT_ID unset).
func contractYAML(projectID string) string {
	project := ""
	if projectID != "" {
		project = fmt.Sprintf("  project_id: %q\n", projectID)
	}
	return fmt.Sprintf(`contract:
%s  programs:
    compliance: %q
    vault: %q
    pricing: %q
    transfer_hook: %q
    redemption: %q
    supply_controller: %q
  rwa_mint: %q
  rwa_decimals: 9
  quote_mint: %q
  supply_config: %q
  vault_config: %q
`, project, pubkeyCompliance, pubkeyVault, pubkeyPricing, pubkeyTransferHook,
		pubkeyRedemption, pubkeySupplyController, pubkeyRWAMint, pubkeyQuoteMint,
		supplyConfig, vaultConfig)
}

// yAML is the YAML `chain:`+`contract:` block counterpart of config_test.go's
// env() — every required chain.*/contract.* field set to a valid base58
// pubkey. No project_id/admin_pubkey (matching env()'s own non-production
// default).
var yAML = chainYAML + contractYAML("")

// TestLoadExampleConfig: the committed server/config.example.yaml must load
// cleanly. Because LoadFile uses KnownFields(true), this fails if the example
// documents a key the fileSchema doesn't declare (or vice versa) — a cheap
// guard against the example and the schema drifting apart.
func TestLoadExampleConfig(t *testing.T) {
	cfg, err := LoadFile("../../config.example.yaml")
	if err != nil {
		t.Fatalf("LoadFile(config.example.yaml) error = %v", err)
	}
	if cfg.KYCProvider != "none" {
		t.Errorf("KYCProvider = %q, want none (example default)", cfg.KYCProvider)
	}
	if cfg.KYCOnfidoRegion != "eu" {
		t.Errorf("KYCOnfidoRegion = %q, want eu (example default)", cfg.KYCOnfidoRegion)
	}
}

// TestLoadFileMissing: a nonexistent path is a startup error, not a silent
// fall-through to defaults.
func TestLoadFileMissing(t *testing.T) {
	if _, err := LoadFile(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Fatal("expected an error for a missing config file")
	}
}

// TestLoadFileEmptyYieldsDefaults: an empty YAML document is missing every
// required chain.*/contract.* field, so it must fail to load — unlike before
// EVM removal, there is no chain-neutral "just defaults" empty config anymore.
func TestLoadFileEmptyYieldsDefaults(t *testing.T) {
	if _, err := LoadFile(writeConfig(t, "")); err == nil {
		t.Fatal("expected an error for an empty config document (chain.*/contract.* is required)")
	}
}

// TestLoadFileMinimalYieldsDefaults: the minimal required chain.*/contract.*
// blocks resolve every other documented default.
func TestLoadFileMinimalYieldsDefaults(t *testing.T) {
	cfg, err := LoadFile(writeConfig(t, yAML))
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %q, want :8080", cfg.HTTPAddr)
	}
	if cfg.Environment != EnvDevelopment {
		t.Errorf("Environment = %q, want development", cfg.Environment)
	}
	if cfg.PersistenceMode != "mongo" {
		t.Errorf("PersistenceMode = %q, want mongo", cfg.PersistenceMode)
	}
	if cfg.IdempotencyTTL != 24*time.Hour {
		t.Errorf("IdempotencyTTL = %v, want 24h", cfg.IdempotencyTTL)
	}
}

// TestLoadFileFullRoundTrip parses a complete YAML — INCLUDING secrets — and
// asserts every field group flattens and resolves correctly: strings, typed
// numbers, durations, the comma-joined trusted proxies list, and secrets.
func TestLoadFileFullRoundTrip(t *testing.T) {
	yaml := fmt.Sprintf(`
environment: development
http:
  addr: ":9090"
  metrics_addr: "0.0.0.0:9100"
  read_timeout: "45s"
  max_header_bytes: 16384
  max_request_body_bytes: 1048576
  trusted_proxies:
    - "10.0.0.1"
    - "172.16.0.0/12"
  cors_allowed_origins:
    - "http://localhost:5173"
    - "https://investor.example"
%smongo:
  uri: "mongodb://mongo:27017"
  db: "custom_db"
ipfs:
  api_url: "http://ipfs:5001"
  backup_kubo_url: "http://ipfs2:5001"
  replication_threshold: 1
security:
  kyc_webhook_hmac_secret: "0123456789012345678901234567890123"
  idempotency_ttl: "1h"
  wallet_session_ttl: "10m"
  jwt_secret: "jwt-secret-0000000000000000000000000000000"
  rate_limit_rps: 25.5
  rate_limit_burst: 40
alerts:
  pending_redemption_sla: "72h"
`, chainYAML+contractYAML("3f2504e0-4f89-41d3-9a0c-0305e82c3301"))
	cfg, err := LoadFile(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"HTTPAddr", cfg.HTTPAddr, ":9090"},
		{"MetricsAddr", cfg.MetricsAddr, "0.0.0.0:9100"},
		{"HTTPReadTimeout", cfg.HTTPReadTimeout, 45 * time.Second},
		{"HTTPMaxHeaderBytes", cfg.HTTPMaxHeaderBytes, 16384},
		{"MaxRequestBodyBytes", cfg.MaxRequestBodyBytes, int64(1048576)},
		{"RPCURL", cfg.RPCURL, "http://127.0.0.1:8899"},
		{"ChainID", cfg.ChainID, int64(1)},
		{"ProjectID", cfg.ProjectID, "3f2504e0-4f89-41d3-9a0c-0305e82c3301"},
		{"MongoURI", cfg.MongoURI, "mongodb://mongo:27017"},
		{"MongoDB", cfg.MongoDB, "custom_db"},
		{"IPFSAPIURL", cfg.IPFSAPIURL, "http://ipfs:5001"},
		{"IPFSBackupKuboURL", cfg.IPFSBackupKuboURL, "http://ipfs2:5001"},
		{"IPFSReplicationThreshold", cfg.IPFSReplicationThreshold, 1},
		{"KYCWebhookHMACSecret", cfg.KYCWebhookHMACSecret, "0123456789012345678901234567890123"},
		{"IdempotencyTTL", cfg.IdempotencyTTL, time.Hour},
		{"WalletSessionTTL", cfg.WalletSessionTTL, 10 * time.Minute},
		{"JWTSecret", cfg.JWTSecret, "jwt-secret-0000000000000000000000000000000"},
		{"RateLimitRPS", cfg.RateLimitRPS, 25.5},
		{"RateLimitBurst", cfg.RateLimitBurst, 40},
		{"PendingRedemptionSLA", cfg.PendingRedemptionSLA, 72 * time.Hour},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
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
	// cors_allowed_origins lives under http:, alongside trusted_proxies — it
	// is an HTTP-transport concern, not a credential/identity one. Asserting
	// it through the FILE path (not just the env map) is what pins the block
	// it belongs to: a key under the wrong block is rejected outright by
	// KnownFields, so this would fail rather than silently ignore it.
	wantOrigins := []string{"http://localhost:5173", "https://investor.example"}
	if len(cfg.CORSAllowedOrigins) != len(wantOrigins) {
		t.Fatalf("CORSAllowedOrigins = %v, want %v", cfg.CORSAllowedOrigins, wantOrigins)
	}
	for i, w := range wantOrigins {
		if cfg.CORSAllowedOrigins[i] != w {
			t.Errorf("CORSAllowedOrigins[%d] = %q, want %q", i, cfg.CORSAllowedOrigins[i], w)
		}
	}
}

// TestLoadFileRejectsUnknownKey: a typo in a security-relevant key must fail
// startup (KnownFields(true)) rather than silently taking a default.
func TestLoadFileRejectsUnknownKey(t *testing.T) {
	const yaml = `
security:
  admin_api_keys: "typo-on-the-key-name"
`
	if _, err := LoadFile(writeConfig(t, yaml)); err == nil {
		t.Fatal("expected an error for an unknown YAML key")
	}
}

// TestLoadFileRejectsMalformedYAML: a syntactically broken document is a
// parse error, not a silent empty-defaults load.
func TestLoadFileRejectsMalformedYAML(t *testing.T) {
	if _, err := LoadFile(writeConfig(t, "http: [unterminated")); err == nil {
		t.Fatal("expected an error for malformed YAML")
	}
}

// TestLoadFileRejectsWrongScalarType: a value of the wrong type (a string
// where an int64 is expected) is a decode error.
func TestLoadFileRejectsWrongScalarType(t *testing.T) {
	if _, err := LoadFile(writeConfig(t, "chain:\n  chain_id: \"not-a-number\"\n")); err == nil {
		t.Fatal("expected an error for a non-integer chain.chain_id")
	}
}

// prodYAML is a minimal production config that passes every fail-closed
// check — the LoadFile counterpart of config_test.go's prodEnv().
var prodYAML = fmt.Sprintf(`
environment: production
%ssecurity:
  kyc_webhook_hmac_secret: "01234567890123456789012345678901"
  jwt_secret: "jwt-secret-0000000000000000000000000000000"
  admin_pubkey: %q
ipfs:
  backup_archive_dir: "./testdata/ipfs-archive"
`, chainYAML+contractYAML("3f2504e0-4f89-41d3-9a0c-0305e82c3301"), pubkeyAdmin)

// TestLoadFileProductionRoundTrips: a valid production YAML (secrets included)
// starts, proving the production fail-closed checks run through LoadFile.
func TestLoadFileProductionRoundTrips(t *testing.T) {
	cfg, err := LoadFile(writeConfig(t, prodYAML))
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if cfg.Environment != EnvProduction {
		t.Errorf("Environment = %q, want production", cfg.Environment)
	}
}

// TestLoadFileProductionRejectsPlaceholderWebhookSecret: the 32-zero string is
// a known placeholder AND exactly 32 bytes, so the length floor alone waves it
// through. It must be caught by the same blocklist that protects JWT_SECRET —
// a forged KYC decision under a guessable webhook secret is relayed on-chain by
// the compliance hot key.
func TestLoadFileProductionRejectsPlaceholderWebhookSecret(t *testing.T) {
	yaml := strings.Replace(prodYAML,
		`kyc_webhook_hmac_secret: "01234567890123456789012345678901"`,
		`kyc_webhook_hmac_secret: "00000000000000000000000000000000"`, 1)
	_, err := LoadFile(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected production startup to fail for a placeholder webhook secret")
	}
	if !strings.Contains(err.Error(), "KYC_WEBHOOK_HMAC_SECRET") {
		t.Fatalf("error = %v, want it to name KYC_WEBHOOK_HMAC_SECRET", err)
	}
}

// TestLoadFileProductionValidationFires: the SAME production checks LoadFromMap
// enforces must also fire when the config arrives as YAML. Each case drops or
// weakens exactly one required value on top of prodYAML and expects startup
// to fail.
func TestLoadFileProductionValidationFires(t *testing.T) {
	cases := map[string]string{
		"weak webhook secret": strings.Replace(prodYAML,
			`kyc_webhook_hmac_secret: "01234567890123456789012345678901"`,
			`kyc_webhook_hmac_secret: "too-short"`, 1),
		"missing jwt secret": strings.Replace(prodYAML,
			`jwt_secret: "jwt-secret-0000000000000000000000000000000"`, "", 1),
		"placeholder jwt secret": strings.Replace(prodYAML,
			`jwt_secret: "jwt-secret-0000000000000000000000000000000"`,
			`jwt_secret: "changeme"`, 1),
		"missing admin pubkey": strings.Replace(prodYAML,
			fmt.Sprintf("  admin_pubkey: %q\n", pubkeyAdmin), "", 1),
		"memory persistence": prodYAML + "mongo:\n  persistence_mode: \"memory\"\n",
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadFile(writeConfig(t, yaml)); err == nil {
				t.Fatalf("expected production startup to fail for %q", name)
			}
		})
	}
}

// TestLoadFileProductionExplicitZeroHonored proves an explicit numeric zero
// (distinct from an omitted key) is carried through the pointer flattening
// and rejected in production where it would disable a control.
func TestLoadFileProductionExplicitZeroHonored(t *testing.T) {
	yaml := strings.Replace(prodYAML, "security:\n", "security:\n  rate_limit_rps: 0\n", 1)
	if _, err := LoadFile(writeConfig(t, yaml)); err == nil {
		t.Fatal("expected production startup to reject security.rate_limit_rps: 0")
	}
}

// TestLoadFileProductionOverride proves the PRODUCTION_ALLOW_* escape hatches
// are reachable from YAML: disabling the rate limit is rejected by default
// but accepted with the explicit override.
func TestLoadFileProductionOverride(t *testing.T) {
	base := strings.Replace(prodYAML, "security:\n", "security:\n  rate_limit_rps: 0\n", 1)
	if _, err := LoadFile(writeConfig(t, base)); err == nil {
		t.Fatal("expected rate_limit_rps: 0 to be rejected without an override")
	}
	withOverride := base + `
production_overrides:
  allow_disabled_rate_limit: true
`
	if _, err := LoadFile(writeConfig(t, withOverride)); err != nil {
		t.Fatalf("expected the explicit override to be accepted: %v", err)
	}
}

// TestExampleConfigParses keeps server/config.example.yaml honest: the shipped
// example must always parse (no unknown keys, well-typed values) and load.
func TestExampleConfigParses(t *testing.T) {
	if _, err := LoadFile("../../config.example.yaml"); err != nil {
		t.Fatalf("config.example.yaml failed to load: %v", err)
	}
}
