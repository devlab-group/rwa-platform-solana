// Package config loads server configuration from a single YAML file whose
// path is passed via --config (see LoadFile). ALL configuration — including
// secrets (the compliance hot key, the KYC webhook HMAC secret, the admin JWT
// secret, Mongo URI, chain RPC, factory address) — lives
// in that file; the operator is responsible for its filesystem permissions,
// exactly as with a .env or supervisor config (secrets-in-file is an
// accepted deployment posture — see server/config.example.yaml).
//
// The YAML is decoded into a flat key/value view (fileSchema.toEnvMap) that
// the pure, I/O-free validation engine (load) then resolves and validates —
// so every default and every production fail-closed check is applied
// identically regardless of how the raw values arrived. That engine is also
// exposed as LoadFromMap for table-driven tests.
package config

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Environment selects the deployment-safety policy Load enforces.
// "production" fails startup on configuration that would otherwise silently
// degrade a security or durability guarantee (empty/weak webhook secret, no
// reachable Mongo); "development" keeps the permissive local/dev-friendly
// defaults.
type Environment string

const (
	EnvDevelopment Environment = "development"
	EnvProduction  Environment = "production"
)

// MinWebhookSecretBytes is the documented minimum length for
// KYC_WEBHOOK_HMAC_SECRET. It's a length floor on the configured string,
// not a true
// entropy measurement — good enough to reject trivial/placeholder secrets
// ("changeme", "secret", ...) without requiring an entropy estimator.
const MinWebhookSecretBytes = 32

// Config is the fully resolved server configuration.
type Config struct {
	// Environment gates production-only startup checks (see Environment's
	// doc comment). Defaults to "development".
	Environment Environment

	// HTTP
	HTTPAddr string

	// Bootstrap: RPC endpoint, indexer start position, and every
	// program/mint address for the program suite — there is no
	// on-chain factory to deploy from, so each program address is
	// provisioned independently.
	// RPCURL is the server's OWN backend RPC endpoint — the indexer and
	// the compliance hot key read/write through it. Unlike the removed
	// solana.public_rpc_url, it is never surfaced to a browser: the
	// SPA's own RPC connection is a build-time value (VITE_SOLANA_RPC_URL) the
	// server neither supplies nor knows.
	RPCURL     string
	Commitment string
	ChainID    int64
	StartSlot  uint64

	ProgramCompliance       string
	ProgramVault            string
	ProgramPricing          string
	ProgramTransferHook     string
	ProgramRedemption       string
	ProgramSupplyController string

	RWAMint   string
	QuoteMint string
	// RWADecimals is the RWA Token-2022 mint's decimals() — required
	// (unlike QuoteDecimals, which may legitimately default to 0)
	// because SeedProject feeds it straight into Project.TokenDecimals,
	// making GET /project authoritative for RWA decimals so the SPAs don't
	// each have to read the mint on-chain themselves. Bounded like the Asset
	// Profile's tokenDecimals (see assets/profile.go's "must be an integer
	// in [0,36]" check) for the same reason: a decimals count outside a
	// sane token range is a config error, not a legitimate value.
	RWADecimals   uint8
	QuoteDecimals uint8
	AdminPubkey   string
	// RedemptionTimeout is the immutable per-deployment redemption
	// timeout (seconds), fed to redemption.Reconcile (see cmd/platform's
	// redemptionTimeoutSeconds for the analogous fallback used when a project
	// record hasn't captured one yet) — there is no on-chain deploy request to
	// capture it from (no factory/deploy-observe flow), so it is
	// config, not a DB-record field.
	RedemptionTimeout int64

	// ClusterGenesis/SupplyConfig are the two domain inputs the
	// mint-attestation digest needs beyond what's already configured
	// (ProgramSupplyController supplies "program" — see
	// eip712.Domain): ClusterGenesis is the target cluster's
	// genesis hash (base58) — the Solana analogue of chainId, binding a
	// signature to exactly one cluster — and SupplyConfig is the
	// rwa-supply-controller's config PDA (base58) — the analogue of
	// verifyingContract. Both MUST be sourced from the bootstrap deployment
	// manifest, never derived in Go. Required + base58-validated, mirroring
	// the six program/mint pubkey fields above.
	//
	// (This codebase does now derive OTHER PDAs in Go — the
	// compliance registry and per-wallet record PDAs the status-write path
	// below signs transactions against, via internal/blockchain.
	// FindProgramAddress — but never these two: unlike a registry/record
	// PDA, which any deployment can always recompute identically from its
	// well-known seeds, supply-config's exact derivation isn't republished
	// here, so it stays config like the addressing invariant originally
	// intended for values with no fixed, universally-known seed.)
	ClusterGenesis string
	SupplyConfig   string

	// VaultConfig is the rwa-vault Config PDA (base58, seeds
	// ["vault-config"] under the vault program — bootstrap.mjs's
	// pdas.vaultConfig) — the value the on-chain rwa-supply-controller
	// actually binds a mint attestation's `vault` field to
	// (Config.vault, set from vault_authority at `initialize` and
	// re-asserted against vault_config.key() at `finalize` — see
	// solana/programs/rwa-supply-controller/src/lib.rs). It is NOT
	// ProgramVault (the vault PROGRAM id, contract.programs.vault) —
	// that is an executable address, not an account, and cannot also be
	// the attestation's vault. Required + base58-validated, alongside
	// contract.supply_config, and MUST be sourced from the bootstrap
	// deployment manifest, never derived in Go (same rule as
	// ClusterGenesis/SupplyConfig above).
	VaultConfig string

	// AllowUnverifiedSupplyConfig is
	// PRODUCTION_ALLOW_UNVERIFIED_SUPPLY_CONFIG's parsed value — the
	// narrowly-named emergency escape hatch (matching the
	// PRODUCTION_ALLOW_UNBOUNDED_FEES / PRODUCTION_ALLOW_WEAK_COMMITMENT
	// pattern) that lets a production deployment boot even though
	// cmd/platform's verifyVaultConfigOnChain could not confirm the
	// on-chain rwa-supply-controller Config account: a
	// pre-`initialize` deployment, an unreachable RPC, or a genuinely wrong
	// vault/domain-field value. Absent/false (the default) means
	// runPlatform refuses to seed the project Active in production
	// without a fully verified account; true is an explicit, operator-chosen
	// opt-in for a deliberate pre-initialization boot. Meaningless outside
	// production, where the cross-check has always been best-effort/
	// non-fatal.
	AllowUnverifiedSupplyConfig bool

	// MaxCheckpointAge bounds how stale the compliance program's
	// IndexerCheckpoint may be before the ReadyCheck reports
	// not-ready. Eligibility answers (GET
	// /compliance/allowed/{address}, Redemption.beneficiaryAllowed) are
	// event-sourced from repos.Investors — if the indexer wedges (see
	// blockchain.Indexer's doc comment) a stale "allowed:true"
	// would otherwise be served indefinitely with nothing to flag it.
	// Defaults to a generous multiple of the 5s indexer poll interval so
	// ordinary poll jitter/backoff never flips readiness; only a genuinely
	// wedged indexer should trip it.
	MaxCheckpointAge time.Duration

	// ComplianceKey is the server's ONE hot key: the
	// compliance-authority key used by compliance.StatusService to
	// sign rwa-compliance set_status instructions (POST /compliance/status
	// and the KYC-webhook auto-allowlist path). Accepts either a
	// base58-encoded 64-byte ed25519 secret key (seed+pubkey, the same form
	// crypto/ed25519.PrivateKey and a Solana CLI keypair file's raw bytes
	// use) OR a filesystem path to a Solana CLI-style keypair JSON file (a
	// JSON array of 64 integers) — see cmd/platform's
	// loadComplianceKey. Empty means "not configured": compliance
	// status writes are then disabled (both paths 501/no-op) rather than
	// erroring at startup — this is intentionally NOT required.
	ComplianceKey string
	// AllowPlaintextComplianceKey is
	// PRODUCTION_ALLOW_PLAINTEXT_COMPLIANCE_KEY's parsed value — the
	// narrowly-named emergency escape hatch (matching the
	// PRODUCTION_ALLOW_UNVERIFIED_SUPPLY_CONFIG /
	// PRODUCTION_ALLOW_WEAK_COMMITMENT pattern) that lets a
	// production deployment configure ComplianceKey as an inline
	// base58 secret rather than a keypair-file path: the
	// compliance key has no keys.Provider abstraction to route
	// through yet (see cmd/platform's loadComplianceKey doc comment)
	// — an inline value keeps the key material directly in this plaintext
	// config file/env. Absent/false (the default) means Load refuses an
	// inline production key; true is an explicit, operator-chosen opt-in.
	AllowPlaintextComplianceKey bool

	// ProjectID is the UUID that identifies this deployment's single Asset
	// Profile. It is set by the operator in config BEFORE the platform runs
	// and acts as a gate: the server rejects any profile whose projectId does
	// not match, and the admin web reads it from GET /api/v1/config rather
	// than minting a fresh one, so the on-chain projectId (keccak256 of this
	// UUID) is fixed by whoever provisions the server. Empty leaves the gate
	// off (development/test); EnvProduction requires it.
	ProjectID string

	// Mongo
	MongoURI string
	MongoDB  string

	// PersistenceMode is "mongo" (default) or "memory". In-memory
	// repositories are only permitted behind this development/test flag:
	// "memory" is an explicit opt-in for local smoke-testing/CI without
	// docker-compose, and is refused in EnvProduction. It does NOT control
	// the fallback behavior when a Mongo connection fails while
	// PersistenceMode=="mongo" — see cmd/platform's connectRepositories,
	// which fails startup on that instead of falling back, in EnvProduction.
	PersistenceMode string

	// IPFS (Kubo HTTP API)
	IPFSAPIURL string

	// IPFS replication: a published asset
	// package is not treated as durably published (see
	// ipfs.ReplicationManager) until at least IPFSReplicationThreshold of
	// the configured backup destinations below have pinned it. Empty
	// destinations means no replication is configured — the platform then
	// falls back to a single local-Kubo-node ipfsPinner exactly as before
	// this existed (a documented, opt-in-to-harden gap, not a silent one:
	// see docs/operator/operator-guide.md).
	//
	// IPFSBackupArchiveDir, if set, adds a local-filesystem reproducible
	// content archive (ipfs.FileArchiveClient) as one backup destination —
	// the option that needs no external commercial service.
	IPFSBackupArchiveDir string
	// IPFSBackupKuboURL, if set, adds a second, independent Kubo node as
	// another backup destination.
	IPFSBackupKuboURL string
	// IPFSReplicationThreshold is how many configured backup destinations
	// (not counting the primary local node) must succeed before a package
	// counts as durably published. Meaningless (and ignored) if no backup
	// destination is configured at all.
	IPFSReplicationThreshold int

	// Security
	KYCWebhookHMACSecret string
	IdempotencyTTL       time.Duration
	WalletChallengeTTL   time.Duration
	// WalletSessionTTL bounds the lifetime of a subject-scoped investor
	// session minted at challenge-verify. Short by design: a
	// lapsed session costs the investor one wallet signature to re-prove
	// ownership, not a lost credential. Mirrors WalletChallengeTTL's knob.
	WalletSessionTTL time.Duration
	// JWTTTL bounds the lifetime of the admin JWT issued at POST /auth/session
	// after a successful wallet-signature challenge. Short-by-design: a lapsed
	// token costs the admin one re-login (a wallet signature), not a lost
	// credential. Replaces the former operator-session TTL — admin auth is now
	// a stateless HMAC JWT (see internal/auth.IssueAdminJWT), not a
	// server-stored operator session.
	JWTTTL time.Duration

	// KYC provider selection (internal/kyc). KYCProvider is "none" (default —
	// the generic KYCWebhookHMACSecret webhook, no server-initiated flow),
	// "sumsub", or "onfido". Only the selected provider's fields below are
	// read; the rest may be empty. The webhook secret for the active provider
	// gates forged KYC decisions the same way KYCWebhookHMACSecret does for the
	// generic path, so production validation requires it (see load).
	KYCProvider string

	KYCSumsubAppToken      string
	KYCSumsubSecretKey     string
	KYCSumsubWebhookSecret string
	KYCSumsubBaseURL       string
	KYCSumsubLevelName     string

	KYCOnfidoAPIToken     string
	KYCOnfidoWebhookToken string
	KYCOnfidoRegion       string
	KYCOnfidoWorkflowID   string
	KYCOnfidoReferrer     string

	// MaxRequestBodyBytes bounds every request body. 0 disables the limit.
	MaxRequestBodyBytes int64

	// RateLimitRPS/RateLimitBurst configure the per-client-IP token bucket
	// (internal/auth.RateLimit). RateLimitRPS<=0 disables rate limiting.
	RateLimitRPS   float64
	RateLimitBurst int

	// TrustedProxies is passed to gin.Engine.SetTrustedProxies (comma-
	// separated IPs/CIDRs). Empty (the default) trusts NO proxies: Gin's
	// c.ClientIP() — which the rate limiter keys on — then uses the raw
	// TCP RemoteAddr only, ignoring X-Forwarded-For entirely. That's the
	// safe default for a directly internet-facing deployment: trusting
	// every proxy (gin's own default before SetTrustedProxies is called
	// explicitly) lets any caller spoof X-Forwarded-For to bypass
	// per-IP rate limiting outright. Set this to the real reverse
	// proxy/load balancer's address when running behind one.
	TrustedProxies []string

	// CORSAllowedOrigins is the exact list of browser origins allowed to call
	// this API cross-origin (scheme+host+port, e.g.
	// "http://localhost:5173"), or empty to disable CORS entirely.
	//
	// Empty is the right default for a deployment that only serves the
	// EMBEDDED admin console: that is same-origin and needs no CORS at all.
	// It exists for the standalone investor SPA (investor-web/), which is a
	// separate deployable served from its own origin.
	//
	// "*" is REFUSED in every environment (see Load): this API accepts an
	// Authorization bearer, and a wildcard origin combined with that would let
	// any page on the internet drive an authenticated session from a victim's
	// browser. List the real origins instead.
	CORSAllowedOrigins []string

	// MetricsAddr, if non-empty, serves Prometheus /metrics on its own
	// listener (deliberately not the public API port — see cmd/platform).
	// Defaults to loopback-only so /metrics is not exposed on all interfaces
	// without auth: /metrics has no authentication
	// of its own, so the safe-by-default posture is a reverse proxy or
	// scraper running on the same host/network namespace. Set this to a
	// non-loopback address explicitly (and put it behind your own
	// auth/firewall) to scrape remotely.
	MetricsAddr string

	// HTTP hardening: read/write/idle timeouts and a header-size cap guard
	// both listeners against slowloris-style slow-client connection
	// exhaustion. Applied to both
	// the public API listener and the metrics listener.
	HTTPReadHeaderTimeout time.Duration
	HTTPReadTimeout       time.Duration
	HTTPWriteTimeout      time.Duration
	HTTPIdleTimeout       time.Duration
	HTTPMaxHeaderBytes    int

	// Alert evaluator thresholds for the pending-redemption SLA and
	// funded-claim-failure evaluators — see internal/alerts.
	PendingRedemptionSLA  time.Duration
	FundedClaimFailureSLA time.Duration

	// JWTSecret is the HMAC-SHA256 signing key for admin JWTs (internal/auth).
	// Empty means admin JWTs cannot be issued/verified; production requires at
	// least MinProductionSecretBytes, same floor as the other secrets. Admin
	// auth is wallet-signature based: POST /auth/challenge issues a
	// single-use message, POST /auth/session recovers the wallet signer and —
	// if it equals AdminPubkey — issues an admin JWT.
	JWTSecret string
}

// envLookup abstracts os.Getenv so tests can supply a fake environment
// without mutating process-global state.
type envLookup func(key string) (string, bool)

// LoadFile reads and parses the YAML configuration at path, then resolves
// defaults and runs every validation (including the production fail-closed
// checks) via the shared engine. Unknown YAML keys are rejected so a typo in
// a security-relevant key can never silently fall back to a default.
func LoadFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: reading %q: %w", path, err)
	}
	var f fileSchema
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	// An empty document (Decode returns io.EOF) is valid: it means "use every
	// default", so fall through with a zero fileSchema.
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("config: parsing %q: %w", path, err)
	}
	return LoadFromMap(f.toEnvMap())
}

// LoadFromMap builds a Config from an explicit key/value map. It is the pure,
// I/O-free validation engine shared by LoadFile (which flattens the parsed
// YAML into such a map) and by the table-driven config tests.
func LoadFromMap(env map[string]string) (Config, error) {
	return load(func(key string) (string, bool) { v, ok := env[key]; return v, ok })
}

// fileSchema is the on-disk YAML shape. It is decoded and then flattened into
// the flat key/value view LoadFromMap consumes (toEnvMap), so the YAML can be
// grouped and human-friendly while the validation engine stays a single flat
// lookup. Scalars whose zero value is a meaningful configuration (numbers,
// booleans) use pointers so "omitted" is distinguishable from "explicitly 0/
// false" — an omitted numeric key must fall through to its documented
// default, while an explicit 0 must be honored (and, in production, rejected
// where a zero disables a control). Empty strings are treated as omitted
// (matching getString), so absent string keys also take their defaults.
type fileSchema struct {
	Environment string `yaml:"environment"`

	HTTP struct {
		Addr                string   `yaml:"addr"`
		MetricsAddr         string   `yaml:"metrics_addr"`
		ReadHeaderTimeout   string   `yaml:"read_header_timeout"`
		ReadTimeout         string   `yaml:"read_timeout"`
		WriteTimeout        string   `yaml:"write_timeout"`
		IdleTimeout         string   `yaml:"idle_timeout"`
		MaxHeaderBytes      *int64   `yaml:"max_header_bytes"`
		MaxRequestBodyBytes *int64   `yaml:"max_request_body_bytes"`
		TrustedProxies      []string `yaml:"trusted_proxies"`
		CORSAllowedOrigins  []string `yaml:"cors_allowed_origins"`
	} `yaml:"http"`

	// Chain is how the server reaches and follows the chain: RPC endpoint,
	// commitment level, which cluster, where the indexer starts, and how
	// stale a checkpoint may get.
	Chain struct {
		RPCURL           string  `yaml:"rpc_url"`
		Commitment       string  `yaml:"commitment"`
		ChainID          *int64  `yaml:"chain_id"`
		StartSlot        *uint64 `yaml:"start_slot"`
		ClusterGenesis   string  `yaml:"cluster_genesis"`
		MaxCheckpointAge string  `yaml:"max_checkpoint_age"`
	} `yaml:"chain"`

	// Contract carries what was deployed: the profile's projectId, every
	// program/mint address for the program suite, and the on-chain
	// parameters fixed at bootstrap. There is no on-chain factory to deploy
	// from, so every program address is provisioned independently rather
	// than discovered from a single factory address. Deployed addresses +
	// auditor live in the DB Project record, not here.
	Contract struct {
		ProjectID string `yaml:"project_id"`
		Programs  struct {
			Compliance       string `yaml:"compliance"`
			Vault            string `yaml:"vault"`
			Pricing          string `yaml:"pricing"`
			TransferHook     string `yaml:"transfer_hook"`
			Redemption       string `yaml:"redemption"`
			SupplyController string `yaml:"supply_controller"`
		} `yaml:"programs"`
		RWAMint           string `yaml:"rwa_mint"`
		RWADecimals       *uint8 `yaml:"rwa_decimals"`
		QuoteMint         string `yaml:"quote_mint"`
		QuoteDecimals     *uint8 `yaml:"quote_decimals"`
		SupplyConfig      string `yaml:"supply_config"`
		VaultConfig       string `yaml:"vault_config"`
		RedemptionTimeout *int64 `yaml:"redemption_timeout"`
	} `yaml:"contract"`

	Mongo struct {
		URI             string `yaml:"uri"`
		DB              string `yaml:"db"`
		PersistenceMode string `yaml:"persistence_mode"`
	} `yaml:"mongo"`

	IPFS struct {
		APIURL               string `yaml:"api_url"`
		BackupArchiveDir     string `yaml:"backup_archive_dir"`
		BackupKuboURL        string `yaml:"backup_kubo_url"`
		ReplicationThreshold *int64 `yaml:"replication_threshold"`
	} `yaml:"ipfs"`

	Security struct {
		KYCWebhookHMACSecret string   `yaml:"kyc_webhook_hmac_secret"`
		IdempotencyTTL       string   `yaml:"idempotency_ttl"`
		WalletChallengeTTL   string   `yaml:"wallet_challenge_ttl"`
		WalletSessionTTL     string   `yaml:"wallet_session_ttl"`
		JWTTTL               string   `yaml:"jwt_ttl"`
		JWTSecret            string   `yaml:"jwt_secret"`
		RateLimitRPS         *float64 `yaml:"rate_limit_rps"`
		RateLimitBurst       *int64   `yaml:"rate_limit_burst"`
		AdminPubkey          string   `yaml:"admin_pubkey"`
		ComplianceKey        string   `yaml:"compliance_key"`
	} `yaml:"security"`

	KYC struct {
		Provider string `yaml:"provider"`
		Sumsub   struct {
			AppToken      string `yaml:"app_token"`
			SecretKey     string `yaml:"secret_key"`
			WebhookSecret string `yaml:"webhook_secret"`
			BaseURL       string `yaml:"base_url"`
			LevelName     string `yaml:"level_name"`
		} `yaml:"sumsub"`
		Onfido struct {
			APIToken     string `yaml:"api_token"`
			WebhookToken string `yaml:"webhook_token"`
			Region       string `yaml:"region"`
			WorkflowID   string `yaml:"workflow_id"`
			Referrer     string `yaml:"referrer"`
		} `yaml:"onfido"`
	} `yaml:"kyc"`

	Alerts struct {
		PendingRedemptionSLA  string `yaml:"pending_redemption_sla"`
		FundedClaimFailureSLA string `yaml:"funded_claim_failure_sla"`
	} `yaml:"alerts"`

	// ProductionOverrides map to the narrowly-named PRODUCTION_ALLOW_*
	// emergency escape hatches. Absent/false means "not overridden"; only an
	// explicit true opts out of a fail-closed check.
	ProductionOverrides struct {
		AllowUnboundedRequestBody   *bool `yaml:"allow_unbounded_request_body"`
		AllowDisabledRateLimit      *bool `yaml:"allow_disabled_rate_limit"`
		AllowWeakCommitment         *bool `yaml:"allow_weak_commitment"`
		AllowUnverifiedSupplyConfig *bool `yaml:"allow_unverified_supply_config"`
		AllowPlaintextComplianceKey *bool `yaml:"allow_plaintext_compliance_key"`
	} `yaml:"production_overrides"`
}

// toEnvMap flattens the parsed YAML into the flat key/value view the
// validation engine (load) consumes. It emits a key only when the operator
// actually supplied a value, so every omitted key falls through to its
// documented default inside load — the one exception being explicit numeric/
// boolean zero values, which are carried through (via the pointer fields) so
// they can be honored and, in production, rejected where a zero disables a
// control.
func (f fileSchema) toEnvMap() map[string]string {
	m := map[string]string{}
	setStr := func(key, v string) {
		if strings.TrimSpace(v) != "" {
			m[key] = v
		}
	}
	setI64 := func(key string, p *int64) {
		if p != nil {
			m[key] = strconv.FormatInt(*p, 10)
		}
	}
	setU64 := func(key string, p *uint64) {
		if p != nil {
			m[key] = strconv.FormatUint(*p, 10)
		}
	}
	setF64 := func(key string, p *float64) {
		if p != nil {
			m[key] = strconv.FormatFloat(*p, 'f', -1, 64)
		}
	}
	setBool := func(key string, p *bool) {
		if p != nil && *p {
			m[key] = "true"
		}
	}
	setU8 := func(key string, p *uint8) {
		if p != nil {
			m[key] = strconv.FormatUint(uint64(*p), 10)
		}
	}

	setStr("ENVIRONMENT", f.Environment)

	setStr("HTTP_ADDR", f.HTTP.Addr)
	setStr("METRICS_ADDR", f.HTTP.MetricsAddr)
	setStr("HTTP_READ_HEADER_TIMEOUT", f.HTTP.ReadHeaderTimeout)
	setStr("HTTP_READ_TIMEOUT", f.HTTP.ReadTimeout)
	setStr("HTTP_WRITE_TIMEOUT", f.HTTP.WriteTimeout)
	setStr("HTTP_IDLE_TIMEOUT", f.HTTP.IdleTimeout)
	setI64("HTTP_MAX_HEADER_BYTES", f.HTTP.MaxHeaderBytes)
	setI64("MAX_REQUEST_BODY_BYTES", f.HTTP.MaxRequestBodyBytes)
	if len(f.HTTP.TrustedProxies) > 0 {
		setStr("TRUSTED_PROXIES", strings.Join(f.HTTP.TrustedProxies, ","))
	}
	if len(f.HTTP.CORSAllowedOrigins) > 0 {
		setStr("CORS_ALLOWED_ORIGINS", strings.Join(f.HTTP.CORSAllowedOrigins, ","))
	}

	setStr("PROJECT_ID", f.Contract.ProjectID)

	setStr("CHAIN_RPC_URL", f.Chain.RPCURL)
	setStr("CHAIN_COMMITMENT", f.Chain.Commitment)
	setI64("CHAIN_ID", f.Chain.ChainID)
	setU64("CHAIN_START_SLOT", f.Chain.StartSlot)
	setStr("CHAIN_CLUSTER_GENESIS", f.Chain.ClusterGenesis)
	setStr("CHAIN_MAX_CHECKPOINT_AGE", f.Chain.MaxCheckpointAge)

	setStr("CONTRACT_PROGRAM_COMPLIANCE", f.Contract.Programs.Compliance)
	setStr("CONTRACT_PROGRAM_VAULT", f.Contract.Programs.Vault)
	setStr("CONTRACT_PROGRAM_PRICING", f.Contract.Programs.Pricing)
	setStr("CONTRACT_PROGRAM_TRANSFER_HOOK", f.Contract.Programs.TransferHook)
	setStr("CONTRACT_PROGRAM_REDEMPTION", f.Contract.Programs.Redemption)
	setStr("CONTRACT_PROGRAM_SUPPLY_CONTROLLER", f.Contract.Programs.SupplyController)
	setStr("CONTRACT_RWA_MINT", f.Contract.RWAMint)
	setU8("CONTRACT_RWA_DECIMALS", f.Contract.RWADecimals)
	setStr("CONTRACT_QUOTE_MINT", f.Contract.QuoteMint)
	setU8("CONTRACT_QUOTE_DECIMALS", f.Contract.QuoteDecimals)
	setI64("CONTRACT_REDEMPTION_TIMEOUT", f.Contract.RedemptionTimeout)
	setStr("CONTRACT_SUPPLY_CONFIG", f.Contract.SupplyConfig)
	setStr("CONTRACT_VAULT_CONFIG", f.Contract.VaultConfig)

	setStr("MONGO_URI", f.Mongo.URI)
	setStr("MONGO_DB", f.Mongo.DB)
	setStr("PERSISTENCE_MODE", f.Mongo.PersistenceMode)

	setStr("IPFS_API_URL", f.IPFS.APIURL)
	setStr("IPFS_BACKUP_ARCHIVE_DIR", f.IPFS.BackupArchiveDir)
	setStr("IPFS_BACKUP_KUBO_URL", f.IPFS.BackupKuboURL)
	setI64("IPFS_REPLICATION_THRESHOLD", f.IPFS.ReplicationThreshold)

	setStr("KYC_WEBHOOK_HMAC_SECRET", f.Security.KYCWebhookHMACSecret)
	setStr("IDEMPOTENCY_TTL", f.Security.IdempotencyTTL)
	setStr("WALLET_CHALLENGE_TTL", f.Security.WalletChallengeTTL)
	setStr("WALLET_SESSION_TTL", f.Security.WalletSessionTTL)
	setStr("JWT_TTL", f.Security.JWTTTL)
	setStr("JWT_SECRET", f.Security.JWTSecret)
	setF64("RATE_LIMIT_RPS", f.Security.RateLimitRPS)
	setI64("RATE_LIMIT_BURST", f.Security.RateLimitBurst)
	setStr("ADMIN_PUBKEY", f.Security.AdminPubkey)
	setStr("COMPLIANCE_KEY", f.Security.ComplianceKey)

	setStr("KYC_PROVIDER", f.KYC.Provider)
	setStr("KYC_SUMSUB_APP_TOKEN", f.KYC.Sumsub.AppToken)
	setStr("KYC_SUMSUB_SECRET_KEY", f.KYC.Sumsub.SecretKey)
	setStr("KYC_SUMSUB_WEBHOOK_SECRET", f.KYC.Sumsub.WebhookSecret)
	setStr("KYC_SUMSUB_BASE_URL", f.KYC.Sumsub.BaseURL)
	setStr("KYC_SUMSUB_LEVEL_NAME", f.KYC.Sumsub.LevelName)
	setStr("KYC_ONFIDO_API_TOKEN", f.KYC.Onfido.APIToken)
	setStr("KYC_ONFIDO_WEBHOOK_TOKEN", f.KYC.Onfido.WebhookToken)
	setStr("KYC_ONFIDO_REGION", f.KYC.Onfido.Region)
	setStr("KYC_ONFIDO_WORKFLOW_ID", f.KYC.Onfido.WorkflowID)
	setStr("KYC_ONFIDO_REFERRER", f.KYC.Onfido.Referrer)

	setStr("PENDING_REDEMPTION_SLA", f.Alerts.PendingRedemptionSLA)
	setStr("FUNDED_CLAIM_FAILURE_SLA", f.Alerts.FundedClaimFailureSLA)

	setBool("PRODUCTION_ALLOW_UNBOUNDED_REQUEST_BODY", f.ProductionOverrides.AllowUnboundedRequestBody)
	setBool("PRODUCTION_ALLOW_DISABLED_RATE_LIMIT", f.ProductionOverrides.AllowDisabledRateLimit)
	setBool("PRODUCTION_ALLOW_WEAK_COMMITMENT", f.ProductionOverrides.AllowWeakCommitment)
	setBool("PRODUCTION_ALLOW_UNVERIFIED_SUPPLY_CONFIG", f.ProductionOverrides.AllowUnverifiedSupplyConfig)
	setBool("PRODUCTION_ALLOW_PLAINTEXT_COMPLIANCE_KEY", f.ProductionOverrides.AllowPlaintextComplianceKey)

	return m
}

func load(lookup envLookup) (Config, error) {
	cfg := Config{
		Environment:          Environment(getString(lookup, "ENVIRONMENT", string(EnvDevelopment))),
		HTTPAddr:             getString(lookup, "HTTP_ADDR", ":8080"),
		MongoURI:             getString(lookup, "MONGO_URI", "mongodb://127.0.0.1:27017"),
		MongoDB:              getString(lookup, "MONGO_DB", "rwa_platform"),
		PersistenceMode:      getString(lookup, "PERSISTENCE_MODE", "mongo"),
		IPFSAPIURL:           getString(lookup, "IPFS_API_URL", "http://127.0.0.1:5001"),
		IPFSBackupArchiveDir: getString(lookup, "IPFS_BACKUP_ARCHIVE_DIR", ""),
		IPFSBackupKuboURL:    getString(lookup, "IPFS_BACKUP_KUBO_URL", ""),
		KYCWebhookHMACSecret: getString(lookup, "KYC_WEBHOOK_HMAC_SECRET", ""),

		ProjectID: getString(lookup, "PROJECT_ID", ""),

		RPCURL:     getString(lookup, "CHAIN_RPC_URL", ""),
		Commitment: getString(lookup, "CHAIN_COMMITMENT", "finalized"),

		ProgramCompliance:       getString(lookup, "CONTRACT_PROGRAM_COMPLIANCE", ""),
		ProgramVault:            getString(lookup, "CONTRACT_PROGRAM_VAULT", ""),
		ProgramPricing:          getString(lookup, "CONTRACT_PROGRAM_PRICING", ""),
		ProgramTransferHook:     getString(lookup, "CONTRACT_PROGRAM_TRANSFER_HOOK", ""),
		ProgramRedemption:       getString(lookup, "CONTRACT_PROGRAM_REDEMPTION", ""),
		ProgramSupplyController: getString(lookup, "CONTRACT_PROGRAM_SUPPLY_CONTROLLER", ""),

		RWAMint:     getString(lookup, "CONTRACT_RWA_MINT", ""),
		QuoteMint:   getString(lookup, "CONTRACT_QUOTE_MINT", ""),
		AdminPubkey: getString(lookup, "ADMIN_PUBKEY", ""),

		ClusterGenesis:              getString(lookup, "CHAIN_CLUSTER_GENESIS", ""),
		SupplyConfig:                getString(lookup, "CONTRACT_SUPPLY_CONFIG", ""),
		VaultConfig:                 getString(lookup, "CONTRACT_VAULT_CONFIG", ""),
		AllowUnverifiedSupplyConfig: getBool(lookup, "PRODUCTION_ALLOW_UNVERIFIED_SUPPLY_CONFIG"),
		ComplianceKey:               getString(lookup, "COMPLIANCE_KEY", ""),
		AllowPlaintextComplianceKey: getBool(lookup, "PRODUCTION_ALLOW_PLAINTEXT_COMPLIANCE_KEY"),

		KYCProvider:            getString(lookup, "KYC_PROVIDER", "none"),
		KYCSumsubAppToken:      getString(lookup, "KYC_SUMSUB_APP_TOKEN", ""),
		KYCSumsubSecretKey:     getString(lookup, "KYC_SUMSUB_SECRET_KEY", ""),
		KYCSumsubWebhookSecret: getString(lookup, "KYC_SUMSUB_WEBHOOK_SECRET", ""),
		KYCSumsubBaseURL:       getString(lookup, "KYC_SUMSUB_BASE_URL", ""),
		KYCSumsubLevelName:     getString(lookup, "KYC_SUMSUB_LEVEL_NAME", ""),
		KYCOnfidoAPIToken:      getString(lookup, "KYC_ONFIDO_API_TOKEN", ""),
		KYCOnfidoWebhookToken:  getString(lookup, "KYC_ONFIDO_WEBHOOK_TOKEN", ""),
		KYCOnfidoRegion:        getString(lookup, "KYC_ONFIDO_REGION", "eu"),
		KYCOnfidoWorkflowID:    getString(lookup, "KYC_ONFIDO_WORKFLOW_ID", ""),
		KYCOnfidoReferrer:      getString(lookup, "KYC_ONFIDO_REFERRER", ""),

		MetricsAddr: getString(lookup, "METRICS_ADDR", "127.0.0.1:9090"),

		JWTSecret: getString(lookup, "JWT_SECRET", ""),
	}

	chainID, err := getInt64(lookup, "CHAIN_ID", 0)
	if err != nil {
		return Config{}, err
	}
	cfg.ChainID = chainID

	startSlot, err := getUint64(lookup, "CHAIN_START_SLOT", 0)
	if err != nil {
		return Config{}, err
	}
	cfg.StartSlot = startSlot

	quoteDecimals, err := getUint64(lookup, "CONTRACT_QUOTE_DECIMALS", 0)
	if err != nil {
		return Config{}, err
	}
	if quoteDecimals > 255 {
		return Config{}, fmt.Errorf("config: CONTRACT_QUOTE_DECIMALS must fit in a byte (0-255), got %d", quoteDecimals)
	}
	cfg.QuoteDecimals = uint8(quoteDecimals)

	// Default 0 here is a placeholder, not a legitimate value — unlike
	// QuoteDecimals, CONTRACT_RWA_DECIMALS is REQUIRED (checked below, in
	// the contract validation block) since SeedProject feeds it straight
	// into Project.TokenDecimals.
	rwaDecimals, err := getUint64(lookup, "CONTRACT_RWA_DECIMALS", 0)
	if err != nil {
		return Config{}, err
	}
	if rwaDecimals > 255 {
		return Config{}, fmt.Errorf("config: CONTRACT_RWA_DECIMALS must fit in a byte (0-255), got %d", rwaDecimals)
	}
	cfg.RWADecimals = uint8(rwaDecimals)

	// Defaults to the same 14-day recommendation cmd/platform's
	// redemptionTimeoutSeconds falls back to for a project record with no
	// captured timeout yet.
	redemptionTimeout, err := getInt64(lookup, "CONTRACT_REDEMPTION_TIMEOUT", 14*24*60*60)
	if err != nil {
		return Config{}, err
	}
	cfg.RedemptionTimeout = redemptionTimeout

	// Default is a generous multiple of the 5s indexer poll tick
	// (startBackgroundLoops) — see MaxCheckpointAge's doc
	// comment.
	maxCheckpointAge, err := getDuration(lookup, "CHAIN_MAX_CHECKPOINT_AGE", 5*time.Minute)
	if err != nil {
		return Config{}, err
	}
	cfg.MaxCheckpointAge = maxCheckpointAge

	idempotencyTTL, err := getDuration(lookup, "IDEMPOTENCY_TTL", 24*time.Hour)
	if err != nil {
		return Config{}, err
	}
	cfg.IdempotencyTTL = idempotencyTTL

	challengeTTL, err := getDuration(lookup, "WALLET_CHALLENGE_TTL", 15*time.Minute)
	if err != nil {
		return Config{}, err
	}
	cfg.WalletChallengeTTL = challengeTTL

	sessionTTL, err := getDuration(lookup, "WALLET_SESSION_TTL", 15*time.Minute)
	if err != nil {
		return Config{}, err
	}
	cfg.WalletSessionTTL = sessionTTL

	jwtTTL, err := getDuration(lookup, "JWT_TTL", 24*time.Hour)
	if err != nil {
		return Config{}, err
	}
	cfg.JWTTTL = jwtTTL

	maxBody, err := getInt64(lookup, "MAX_REQUEST_BODY_BYTES", 2<<20) // 2 MiB
	if err != nil {
		return Config{}, err
	}
	cfg.MaxRequestBodyBytes = maxBody

	rateLimitRPS, err := getFloat64(lookup, "RATE_LIMIT_RPS", 50)
	if err != nil {
		return Config{}, err
	}
	cfg.RateLimitRPS = rateLimitRPS

	rateLimitBurst, err := getInt64(lookup, "RATE_LIMIT_BURST", 100)
	if err != nil {
		return Config{}, err
	}
	cfg.RateLimitBurst = int(rateLimitBurst)

	ipfsReplicationThreshold, err := getInt64(lookup, "IPFS_REPLICATION_THRESHOLD", 1)
	if err != nil {
		return Config{}, err
	}
	cfg.IPFSReplicationThreshold = int(ipfsReplicationThreshold)

	if v, ok := lookup("TRUSTED_PROXIES"); ok && strings.TrimSpace(v) != "" {
		var proxies []string
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				proxies = append(proxies, p)
			}
		}
		cfg.TrustedProxies = proxies
	}

	if v, ok := lookup("CORS_ALLOWED_ORIGINS"); ok && strings.TrimSpace(v) != "" {
		var origins []string
		for _, o := range strings.Split(v, ",") {
			if o = strings.TrimSpace(o); o != "" {
				origins = append(origins, o)
			}
		}
		cfg.CORSAllowedOrigins = origins
	}

	pendingSLA, err := getDuration(lookup, "PENDING_REDEMPTION_SLA", 48*time.Hour)
	if err != nil {
		return Config{}, err
	}
	cfg.PendingRedemptionSLA = pendingSLA

	fundedSLA, err := getDuration(lookup, "FUNDED_CLAIM_FAILURE_SLA", 24*time.Hour)
	if err != nil {
		return Config{}, err
	}
	cfg.FundedClaimFailureSLA = fundedSLA

	if cfg.HTTPReadHeaderTimeout, err = getDuration(lookup, "HTTP_READ_HEADER_TIMEOUT", 5*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.HTTPReadTimeout, err = getDuration(lookup, "HTTP_READ_TIMEOUT", 30*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.HTTPWriteTimeout, err = getDuration(lookup, "HTTP_WRITE_TIMEOUT", 60*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.HTTPIdleTimeout, err = getDuration(lookup, "HTTP_IDLE_TIMEOUT", 120*time.Second); err != nil {
		return Config{}, err
	}
	maxHeaderBytes, err := getInt64(lookup, "HTTP_MAX_HEADER_BYTES", 32<<10) // 32 KiB
	if err != nil {
		return Config{}, err
	}
	cfg.HTTPMaxHeaderBytes = int(maxHeaderBytes)

	if cfg.RPCURL == "" {
		return Config{}, errors.New("config: chain.rpc_url is required")
	}
	// The indexer has NO reorg handling by design (see
	// internal/blockchain/indexer.go's doc comment): correctness rests
	// entirely on every RPC call being made at a commitment level that
	// cannot be rolled back. An unrecognized value was previously
	// accepted and passed straight through to GetSlot/
	// GetSignaturesForAddress/GetTransaction verbatim.
	switch cfg.Commitment {
	case "processed", "confirmed", "finalized":
	default:
		return Config{}, fmt.Errorf("config: chain.commitment must be %q, %q, or %q, got %q", "processed", "confirmed", "finalized", cfg.Commitment)
	}
	requiredPubkeys := map[string]string{
		"contract.programs.compliance":        cfg.ProgramCompliance,
		"contract.programs.vault":             cfg.ProgramVault,
		"contract.programs.pricing":           cfg.ProgramPricing,
		"contract.programs.transfer_hook":     cfg.ProgramTransferHook,
		"contract.programs.redemption":        cfg.ProgramRedemption,
		"contract.programs.supply_controller": cfg.ProgramSupplyController,
		"contract.rwa_mint":                   cfg.RWAMint,
		"contract.quote_mint":                 cfg.QuoteMint,
		// The two mint-attestation domain inputs assets.NewRecordService
		// needs beyond the supply-controller program id above — see
		// Config.ClusterGenesis's doc comment. isBase58Pubkey's "decodes
		// to exactly 32 bytes" check is exactly what a cluster genesis hash
		// needs too (it's a 32-byte hash, same shape as a pubkey), so it's
		// reused unmodified rather than adding a separate isBase58Hash.
		"chain.cluster_genesis":  cfg.ClusterGenesis,
		"contract.supply_config": cfg.SupplyConfig,
		// contract.vault_config is the rwa-vault Config PDA the
		// on-chain rwa-supply-controller actually binds the mint
		// attestation's `vault` field to — see
		// Config.VaultConfig's doc comment.
		"contract.vault_config": cfg.VaultConfig,
	}
	for name, v := range requiredPubkeys {
		if v == "" {
			return Config{}, fmt.Errorf("config: %s is required", name)
		}
		if !isBase58Pubkey(v) {
			return Config{}, fmt.Errorf("config: %s=%q is not a valid base58 Solana public key", name, v)
		}
	}
	if cfg.AdminPubkey != "" && !isBase58Pubkey(cfg.AdminPubkey) {
		return Config{}, fmt.Errorf("config: security.admin_pubkey=%q is not a valid base58 Solana public key", cfg.AdminPubkey)
	}
	if cfg.ChainID <= 0 {
		return Config{}, fmt.Errorf("config: chain.chain_id must be positive, got %d", cfg.ChainID)
	}
	// Bounded to the SAME [1 day, 365 days] range
	// solana/programs/rwa-redemption/src/lib.rs's `initialize` enforces
	// on-chain (MIN_REDEMPTION_TIMEOUT/MAX_REDEMPTION_TIMEOUT) — this server
	// value feeds redemption.Reconcile's derived TimeoutAt directly
	// (see Config.RedemptionTimeout's doc comment) with no on-chain
	// cross-check today, so an obviously-out-of-range value (a typo, a
	// unit mixup) would otherwise only surface as silently wrong
	// claimable/timeout dates rather than a startup failure.
	const (
		minRedemptionTimeout = 24 * 60 * 60       // 1 day, seconds
		maxRedemptionTimeout = 365 * 24 * 60 * 60 // 365 days, seconds
	)
	if cfg.RedemptionTimeout < minRedemptionTimeout || cfg.RedemptionTimeout > maxRedemptionTimeout {
		return Config{}, fmt.Errorf("config: contract.redemption_timeout must be within [%d, %d] seconds ([1 day, 365 days], matching the on-chain rwa-redemption program's bound), got %d", minRedemptionTimeout, maxRedemptionTimeout, cfg.RedemptionTimeout)
	}
	// contract.rwa_decimals is REQUIRED (unlike quote_decimals, which may
	// legitimately default to 0): SeedProject feeds it straight into
	// Project.TokenDecimals, so an omitted value would silently report RWA
	// decimals=0 on GET /project instead of failing loudly at startup. 0
	// itself IS a value getUint64's default would also produce for an
	// omitted key, so presence (not just non-zero-ness) is what's checked
	// here — an operator who genuinely wants 0 decimals must still say so
	// explicitly.
	if _, ok := lookup("CONTRACT_RWA_DECIMALS"); !ok {
		return Config{}, errors.New("config: contract.rwa_decimals is required")
	}
	// Same [0,36] bound the Asset Profile's tokenDecimals enforces
	// (assets/profile.go) — kept in step so a projectId's on-chain decimals
	// and its profile metadata can never legitimately disagree on the
	// sane range, even though the profile itself is validated separately.
	if cfg.RWADecimals > 36 {
		return Config{}, fmt.Errorf("config: contract.rwa_decimals must be in [0,36], got %d", cfg.RWADecimals)
	}

	// CORS origins are validated in EVERY environment, not just production:
	// a wildcard is never a legitimate value for an API that accepts an
	// Authorization bearer, and a malformed origin silently never matches
	// (browsers send the exact scheme+host+port), which presents as "CORS is
	// broken" with nothing in the logs to say why.
	for _, origin := range cfg.CORSAllowedOrigins {
		switch {
		case origin == "*":
			return Config{}, errors.New(`config: http.cors_allowed_origins must not contain "*" — this API accepts an Authorization bearer, and a wildcard origin would let any site drive an authenticated session from a victim's browser; list the exact origins instead`)
		case strings.HasSuffix(origin, "/"):
			return Config{}, fmt.Errorf("config: http.cors_allowed_origins %q must not have a trailing slash — a browser's Origin header is scheme+host+port only, so this would never match", origin)
		case !strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://"):
			return Config{}, fmt.Errorf("config: http.cors_allowed_origins %q must be a full origin including the scheme, e.g. %q", origin, "http://localhost:5173")
		}
	}

	if cfg.Environment != EnvDevelopment && cfg.Environment != EnvProduction {
		return Config{}, fmt.Errorf("config: ENVIRONMENT must be %q or %q, got %q", EnvDevelopment, EnvProduction, cfg.Environment)
	}
	if cfg.PersistenceMode != "mongo" && cfg.PersistenceMode != "memory" {
		return Config{}, fmt.Errorf("config: PERSISTENCE_MODE must be %q or %q, got %q", "mongo", "memory", cfg.PersistenceMode)
	}
	// KYC provider selection + per-provider required fields, enforced in every
	// environment: picking a provider you haven't configured is a
	// misconfiguration, not a degrade path. Production additionally enforces
	// webhook-secret strength below.
	switch cfg.KYCProvider {
	case "none":
		// generic KYCWebhookHMACSecret path; nothing provider-specific required
	case "sumsub":
		for name, v := range map[string]string{
			"KYC_SUMSUB_APP_TOKEN":      cfg.KYCSumsubAppToken,
			"KYC_SUMSUB_SECRET_KEY":     cfg.KYCSumsubSecretKey,
			"KYC_SUMSUB_WEBHOOK_SECRET": cfg.KYCSumsubWebhookSecret,
		} {
			if v == "" {
				return Config{}, fmt.Errorf("config: %s is required when KYC_PROVIDER=sumsub", name)
			}
		}
	case "onfido":
		for name, v := range map[string]string{
			"KYC_ONFIDO_API_TOKEN":     cfg.KYCOnfidoAPIToken,
			"KYC_ONFIDO_WEBHOOK_TOKEN": cfg.KYCOnfidoWebhookToken,
			"KYC_ONFIDO_WORKFLOW_ID":   cfg.KYCOnfidoWorkflowID,
		} {
			if v == "" {
				return Config{}, fmt.Errorf("config: %s is required when KYC_PROVIDER=onfido", name)
			}
		}
		switch cfg.KYCOnfidoRegion {
		case "eu", "us", "ca":
		default:
			return Config{}, fmt.Errorf("config: KYC_ONFIDO_REGION must be eu, us, or ca, got %q", cfg.KYCOnfidoRegion)
		}
	default:
		return Config{}, fmt.Errorf("config: KYC_PROVIDER must be %q, %q, or %q, got %q", "none", "sumsub", "onfido", cfg.KYCProvider)
	}

	// An empty KYC_WEBHOOK_HMAC_SECRET makes VerifyHMAC's underlying
	// HMAC-SHA256 computable by anyone (an empty key is still a valid HMAC
	// key), so an unauthenticated caller could forge a KYC decision. A
	// configured-but-weak secret (e.g. a placeholder like "changeme") is
	// never acceptable regardless of environment; an entirely absent secret
	// is tolerated outside production as "webhook feature disabled" (see
	// cmd/platform's buildApp, which only wires compliance.WebhookService
	// when this is non-empty).
	if n := len(cfg.KYCWebhookHMACSecret); n > 0 && n < MinWebhookSecretBytes {
		return Config{}, fmt.Errorf("config: KYC_WEBHOOK_HMAC_SECRET is %d bytes, below the documented minimum of %d", n, MinWebhookSecretBytes)
	}
	// A configured-but-weak JWT signing key is never acceptable regardless of
	// environment (an admin JWT signed with a short key is trivially forgeable);
	// an entirely absent secret is tolerated outside production as "admin JWT
	// auth disabled" (buildApp only wires the admin auth service when it is set).
	if n := len(cfg.JWTSecret); n > 0 && n < MinProductionSecretBytes {
		return Config{}, fmt.Errorf("config: JWT_SECRET is %d bytes, below the documented minimum of %d", n, MinProductionSecretBytes)
	}
	// A malformed PROJECT_ID would be rejected later at profile create (the gate
	// compares it against the stored profile's projectId); reject it up front so
	// a typo is caught at startup, not on the first create attempt.
	if cfg.ProjectID != "" && !isUUID(cfg.ProjectID) {
		return Config{}, fmt.Errorf("config: PROJECT_ID %q is not a valid UUID", cfg.ProjectID)
	}
	if cfg.Environment == EnvProduction {
		// Whatever KYC path is active must authenticate its webhook: an empty
		// secret would permit forged KYC decisions once relayed on-chain. For
		// the generic ("none") path that is KYC_WEBHOOK_HMAC_SECRET; for a real
		// provider it is that provider's own webhook secret (required in every
		// environment above, and strength-checked for the operator-chosen
		// Sumsub secret below). The Onfido webhook token is issued by Onfido, so
		// it is required non-empty but not held to our operator-secret length
		// floor.
		switch cfg.KYCProvider {
		case "none":
			if cfg.KYCWebhookHMACSecret == "" {
				return Config{}, errors.New("config: KYC_WEBHOOK_HMAC_SECRET must be set in production (ENVIRONMENT=production) — an empty secret would permit forged KYC decisions once relayed on-chain")
			}
		case "sumsub":
			if len(cfg.KYCSumsubWebhookSecret) < MinProductionSecretBytes {
				return Config{}, fmt.Errorf("config: KYC_SUMSUB_WEBHOOK_SECRET must be at least %d bytes in production, got %d", MinProductionSecretBytes, len(cfg.KYCSumsubWebhookSecret))
			}
			if weakProductionSecrets[strings.ToLower(cfg.KYCSumsubWebhookSecret)] {
				return Config{}, errors.New("config: KYC_SUMSUB_WEBHOOK_SECRET is a known placeholder value and must not be used in production")
			}
		case "onfido":
			if weakProductionSecrets[strings.ToLower(cfg.KYCOnfidoWebhookToken)] {
				return Config{}, errors.New("config: KYC_ONFIDO_WEBHOOK_TOKEN is a known placeholder value and must not be used in production")
			}
		}
		if cfg.PersistenceMode != "mongo" {
			return Config{}, fmt.Errorf("config: PERSISTENCE_MODE=%q is not allowed in production; volatile in-memory repositories would silently drop project guards, idempotency records, and audit history on restart", cfg.PersistenceMode)
		}
		// The projectId gate must be armed in production: it fixes which Asset
		// Profile this deployment will accept before anything is created, so an
		// unset value would let the first caller choose the projectId.
		if cfg.ProjectID == "" {
			return Config{}, errors.New("config: PROJECT_ID must be set in production — it fixes the deployment's projectId and gates which Asset Profile the server will accept")
		}
		// The compliance key has no keys.Provider abstraction to
		// route through yet (see cmd/platform's loadComplianceKey doc
		// comment). An INLINE base58 secret (as opposed to a keypair-file
		// path) keeps the key material directly in this plaintext config
		// file/env, so require the file-path form unless the operator
		// explicitly opts in.
		if isInlineSecretKey(cfg.ComplianceKey) && !cfg.AllowPlaintextComplianceKey {
			return Config{}, errors.New("config: security.compliance_key is an inline base58 secret key in production, keeping it in plaintext config; use a keypair file path instead, or set PRODUCTION_ALLOW_PLAINTEXT_COMPLIANCE_KEY=true to explicitly override")
		}
		// Admin auth is wallet-signature -> JWT (single-admin model):
		// require a configured admin wallet to authorize against and an
		// HMAC secret to sign/verify the JWT with, so admin routes are
		// actually authenticated. An unset admin wallet would leave admin
		// login silently impossible in production (createSession 501s with
		// no configured admin) despite config validation passing.
		if cfg.AdminPubkey == "" {
			return Config{}, errors.New("config: security.admin_pubkey must be set in production — admin routes authenticate a wallet-signature JWT against this address")
		}
		if cfg.JWTSecret == "" {
			return Config{}, errors.New("config: JWT_SECRET must be set in production so admin JWTs are signed with a real HMAC key")
		}
		// In production, require at least one genuinely independent
		// destination and validate 1 <= threshold <= destination count.
		// Without a configured backup, IPFS_API_URL
		// alone falls back to a single bare local Kubo client with no
		// replication and no durable-publication tracking at all — a
		// silent single-point-of-failure for mint evidence in production.
		if cfg.IPFSAPIURL != "" {
			backupCount := 0
			if cfg.IPFSBackupArchiveDir != "" {
				backupCount++
			}
			if cfg.IPFSBackupKuboURL != "" {
				backupCount++
			}
			if backupCount == 0 {
				return Config{}, errors.New("config: IPFS_API_URL is set but no backup destination is configured (IPFS_BACKUP_ARCHIVE_DIR or IPFS_BACKUP_KUBO_URL) — production requires at least one independent replication destination")
			}
			if cfg.IPFSReplicationThreshold < 1 || cfg.IPFSReplicationThreshold > backupCount {
				return Config{}, fmt.Errorf("config: IPFS_REPLICATION_THRESHOLD=%d must be between 1 and the configured backup destination count (%d) in production", cfg.IPFSReplicationThreshold, backupCount)
			}
		}

		// A production configuration must not accept disabled safeguards or
		// trivial privileged credentials. A syntactically
		// valid production environment must not be able to permit rapid
		// guessing of weak credentials, unbounded request bodies,
		// premature transaction finality, uncontrolled fees, or a
		// self-inflicted denial of service through a zero/negative
		// duration or limit. Every "disabled control" check below (body
		// limit, rate limit, fee cap) has a narrowly-named
		// PRODUCTION_ALLOW_* emergency override; every positive-bound
		// check does not, since a non-positive duration/burst/
		// confirmation count is never a legitimate production choice —
		// only ever a misconfiguration.
		if err := validateProductionSecrets(cfg); err != nil {
			return Config{}, err
		}
		if err := validateProductionBounds(lookup, cfg); err != nil {
			return Config{}, err
		}
	}

	return cfg, nil
}

func getString(lookup envLookup, key, def string) string {
	if v, ok := lookup(key); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return def
}

// getBool reads a narrowly-scoped boolean env var — used only for the
// emergency-override knobs (e.g. PRODUCTION_ALLOW_*): exactly
// "true" (case-insensitive) opts in, anything else (including unset,
// empty, or a typo) is treated as false/not-overridden — deliberately
// fail-safe rather than permissive-by-default parsing.
func getBool(lookup envLookup, key string) bool {
	v, ok := lookup(key)
	return ok && strings.EqualFold(strings.TrimSpace(v), "true")
}

// MinProductionSecretBytes is the documented minimum length for the JWT
// signing secret in production — randomly generated secrets should be at
// least 32 bytes. A length floor, same honest limitation as
// MinWebhookSecretBytes — not a true entropy measurement.
const MinProductionSecretBytes = 32

// weakProductionSecrets are known placeholder/trivial values rejected
// outright regardless of length (including the obvious single-character
// cases like "a" and "b"). Matched case-insensitively.
var weakProductionSecrets = map[string]bool{
	"a": true, "b": true, "admin": true, "operator": true, "password": true,
	"changeme": true, "change-me": true, "change_me": true, "secret": true,
	"test": true, "default": true, "placeholder": true, "example": true,
	"00000000000000000000000000000000": true,
}

// validateProductionSecrets enforces the production length/placeholder rules
// for both HMAC secrets the server holds. ADMIN_ADDRESS is a public wallet
// address, not a secret, so it is not checked here.
//
// The placeholder blocklist matters as much for the webhook secret as for the
// JWT one: every other entry in weakProductionSecrets is shorter than the
// 32-byte floor and so would be caught by length alone, but the 32-zero string
// is exactly 32 bytes and sails through it. A forged KYC decision is relayed
// on-chain by the compliance hot key, so that secret gets the same treatment.
func validateProductionSecrets(cfg Config) error {
	if len(cfg.JWTSecret) < MinProductionSecretBytes {
		return fmt.Errorf("config: JWT_SECRET must be at least %d bytes in production, got %d", MinProductionSecretBytes, len(cfg.JWTSecret))
	}
	if weakProductionSecrets[strings.ToLower(cfg.JWTSecret)] {
		return errors.New("config: JWT_SECRET is a known placeholder value and must not be used in production")
	}
	// The generic KYC webhook secret is only the active authentication path
	// when KYC_PROVIDER=none; with a real provider configured its own webhook
	// secret is checked in load's production block instead, and this value is
	// unused (and typically empty).
	if cfg.KYCProvider == "none" {
		if len(cfg.KYCWebhookHMACSecret) < MinProductionSecretBytes {
			return fmt.Errorf("config: KYC_WEBHOOK_HMAC_SECRET must be at least %d bytes in production, got %d", MinProductionSecretBytes, len(cfg.KYCWebhookHMACSecret))
		}
		if weakProductionSecrets[strings.ToLower(cfg.KYCWebhookHMACSecret)] {
			return errors.New("config: KYC_WEBHOOK_HMAC_SECRET is a known placeholder value and must not be used in production")
		}
	}
	return nil
}

// base58Alphabet is the Bitcoin/Solana base58 alphabet: digits and
// letters, minus the visually-ambiguous 0/O and I/l.
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58DecodedByteLen returns the number of bytes s decodes to as base58,
// or -1 if s contains a character outside base58Alphabet. Shared by
// isBase58Pubkey (32 bytes) and isInlineSecretKey (64 bytes) below.
func base58DecodedByteLen(s string) int {
	for _, c := range s {
		if !strings.ContainsRune(base58Alphabet, c) {
			return -1
		}
	}
	n := new(big.Int)
	base := big.NewInt(58)
	for _, c := range s {
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(strings.IndexRune(base58Alphabet, c))))
	}
	decoded := n.Bytes()
	// Each leading '1' character encodes one leading zero byte that
	// big.Int.Bytes() drops, so add those back in before checking length.
	for i := 0; i < len(s) && s[i] == '1'; i++ {
		decoded = append([]byte{0}, decoded...)
	}
	return len(decoded)
}

// isBase58Pubkey reports whether s is the base58 encoding of a 32-byte
// Solana public key (every Solana account/mint/program address is exactly
// 32 bytes). A small local check so the config package stays free of a
// base58/solana-go dependency for one predicate.
func isBase58Pubkey(s string) bool {
	return s != "" && base58DecodedByteLen(s) == 32
}

// isInlineSecretKey reports whether s decodes as base58 to exactly a
// 64-byte ed25519 secret key — the INLINE form cmd/platform's
// loadComplianceKey accepts for security.compliance_key (seed+pubkey),
// as opposed to a filesystem path to a keypair JSON file. Mirrors
// loadComplianceKey's own "try base58 first" resolution exactly (a
// value that isn't valid base58 at all — e.g. an ordinary filesystem path,
// which contains '/' and '.' — always reports false here, i.e. is treated
// as the file-path form). Used only by the production plaintext-key check
// below.
func isInlineSecretKey(s string) bool {
	return s != "" && base58DecodedByteLen(s) == ed25519.PrivateKeySize
}

// isUUID reports whether s is a canonical 8-4-4-4-12 hex UUID string
// (case-insensitive, any version). Kept in step with the projectId check the
// assets package enforces on the profile document, so a projectId accepted at
// config load is the same shape accepted at profile create.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// validateProductionBounds enforces positive lower bounds (and, for the
// three genuinely "disabled" controls, an explicit narrowly-named
// emergency override) across every security duration, body/header limit,
// rate/burst setting, confirmation count, and fee cap.
func validateProductionBounds(lookup envLookup, cfg Config) error {
	positiveDurations := map[string]time.Duration{
		"IDEMPOTENCY_TTL":          cfg.IdempotencyTTL,
		"WALLET_CHALLENGE_TTL":     cfg.WalletChallengeTTL,
		"WALLET_SESSION_TTL":       cfg.WalletSessionTTL,
		"JWT_TTL":                  cfg.JWTTTL,
		"HTTP_READ_HEADER_TIMEOUT": cfg.HTTPReadHeaderTimeout,
		"HTTP_READ_TIMEOUT":        cfg.HTTPReadTimeout,
		"HTTP_WRITE_TIMEOUT":       cfg.HTTPWriteTimeout,
		"HTTP_IDLE_TIMEOUT":        cfg.HTTPIdleTimeout,
		"PENDING_REDEMPTION_SLA":   cfg.PendingRedemptionSLA,
		"FUNDED_CLAIM_FAILURE_SLA": cfg.FundedClaimFailureSLA,
	}
	for name, d := range positiveDurations {
		if d <= 0 {
			return fmt.Errorf("config: %s must be positive in production, got %s", name, d)
		}
	}

	if cfg.HTTPMaxHeaderBytes <= 0 {
		return errors.New("config: HTTP_MAX_HEADER_BYTES must be positive in production")
	}

	if cfg.MaxRequestBodyBytes <= 0 && !getBool(lookup, "PRODUCTION_ALLOW_UNBOUNDED_REQUEST_BODY") {
		return errors.New("config: MAX_REQUEST_BODY_BYTES must be positive in production (<=0 disables the request body limit) — set PRODUCTION_ALLOW_UNBOUNDED_REQUEST_BODY=true to explicitly override")
	}
	if cfg.RateLimitRPS <= 0 && !getBool(lookup, "PRODUCTION_ALLOW_DISABLED_RATE_LIMIT") {
		return errors.New("config: RATE_LIMIT_RPS must be positive in production (<=0 disables per-IP rate limiting) — set PRODUCTION_ALLOW_DISABLED_RATE_LIMIT=true to explicitly override")
	}
	if cfg.RateLimitRPS > 0 && cfg.RateLimitBurst <= 0 {
		return errors.New("config: RATE_LIMIT_BURST must be positive in production whenever RATE_LIMIT_RPS is enabled")
	}
	// The indexer's correctness rests entirely on "finalized" — see the
	// commitment validation above. A weaker value is
	// syntactically valid (useful for local/dev iteration against a
	// single-validator test cluster with no forks) but must be an
	// explicit, narrowly-named opt-out in production, matching every
	// other genuinely-disabled control's PRODUCTION_ALLOW_* pattern.
	if cfg.Commitment != "finalized" && !getBool(lookup, "PRODUCTION_ALLOW_WEAK_COMMITMENT") {
		return fmt.Errorf("config: chain.commitment=%q is weaker than finalized in production — the indexer has no reorg handling and correctness depends on finalized — set PRODUCTION_ALLOW_WEAK_COMMITMENT=true to explicitly override", cfg.Commitment)
	}
	// A plaintext RPC endpoint to a non-loopback host is MITM-
	// injectable — a network attacker could forge "finalized" Solana
	// RPC responses wholesale, compounding the commitment check's
	// fail-closed posture with nothing to actually trust it against.
	if err := requireProductionSafeURL("chain.rpc_url", cfg.RPCURL); err != nil {
		return err
	}
	return nil
}

// requireProductionSafeURL enforces https for rawURL (named name in error
// messages) in production, unless its host is loopback (localhost/
// 127.0.0.1/::1, for local testing) — see validateProductionBounds's call
// site for why this matters for the server's own backend RPC
// endpoint specifically.
func requireProductionSafeURL(name, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("config: %s=%q is not a valid URL: %w", name, rawURL, err)
	}
	if u.Scheme == "https" {
		return nil
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return nil
	}
	return fmt.Errorf("config: %s=%q must use https in production (loopback hosts are exempt) — use an https endpoint, or localhost/127.0.0.1 for local testing", name, rawURL)
}

func getInt64(lookup envLookup, key string, def int64) (int64, error) {
	v, ok := lookup(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("config: invalid %s=%q: %w", key, v, err)
	}
	return n, nil
}

func getFloat64(lookup envLookup, key string, def float64) (float64, error) {
	v, ok := lookup(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def, nil
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("config: invalid %s=%q: %w", key, v, err)
	}
	return n, nil
}

func getUint64(lookup envLookup, key string, def uint64) (uint64, error) {
	v, ok := lookup(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def, nil
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("config: invalid %s=%q: %w", key, v, err)
	}
	return n, nil
}

func getDuration(lookup envLookup, key string, def time.Duration) (time.Duration, error) {
	v, ok := lookup(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: invalid %s=%q: %w", key, v, err)
	}
	return d, nil
}
