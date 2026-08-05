// Command platform boots the self-hosted RWA platform server: it loads
// config, connects to MongoDB (falling back to an in-memory store if Mongo
// is unreachable, so local smoke-testing works without docker-compose) and
// to the Solana RPC endpoint, wires every workflow service, and serves the
// Gin API.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/mr-tron/base58"

	"github.com/rwa-platform/server/internal/alerts"
	"github.com/rwa-platform/server/internal/api"
	"github.com/rwa-platform/server/internal/assets"
	"github.com/rwa-platform/server/internal/auditlog"
	"github.com/rwa-platform/server/internal/auth"
	"github.com/rwa-platform/server/internal/blockchain"
	"github.com/rwa-platform/server/internal/compliance"
	"github.com/rwa-platform/server/internal/config"
	"github.com/rwa-platform/server/internal/dal"
	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/mongodb"
	"github.com/rwa-platform/server/internal/dal/repository"
	"github.com/rwa-platform/server/internal/ipfs"
	"github.com/rwa-platform/server/internal/keys"
	"github.com/rwa-platform/server/internal/kyc"
	"github.com/rwa-platform/server/internal/metrics"
	"github.com/rwa-platform/server/internal/project"
	"github.com/rwa-platform/server/internal/redemption"
	"github.com/rwa-platform/server/internal/sales"
	"github.com/rwa-platform/server/internal/txindex"
	"github.com/rwa-platform/server/internal/webui"

	mongodriver "go.mongodb.org/mongo-driver/v2/mongo"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	configPath := flag.String("config", "", "path to the YAML configuration file (required)")
	flag.Parse()

	if *configPath == "" {
		log.Fatalf("config: --config <path> is required")
	}
	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	repos, mongoClient := connectRepositories(ctx, cfg)
	if mongoClient != nil {
		defer mongoClient.Disconnect(context.Background())
	}

	runPlatform(ctx, cfg, repos, mongoClient)
}

// serveHTTP brings up the public API listener (plus, if configured, the
// separate /metrics listener) and blocks until ctx is done, running the
// graceful-shutdown sequence (both listeners, then onShutdown — zeroing any
// hot-key material still held) before returning.
// chainLabel is appended to the startup log line (e.g. "chainId=901").
func serveHTTP(ctx context.Context, cfg config.Config, handler http.Handler, onShutdown func(), chainLabel string) {
	// Conservative read/write/idle timeouts and a header-size cap on
	// every listener — bare http.Server has none of these by default, which
	// is what makes an internet-facing listener vulnerable to slowloris-
	// style slow-client connection exhaustion.
	srv := &http.Server{
		Addr: cfg.HTTPAddr, Handler: handler,
		ReadHeaderTimeout: cfg.HTTPReadHeaderTimeout, ReadTimeout: cfg.HTTPReadTimeout,
		WriteTimeout: cfg.HTTPWriteTimeout, IdleTimeout: cfg.HTTPIdleTimeout,
		MaxHeaderBytes: cfg.HTTPMaxHeaderBytes,
	}

	var metricsSrv *http.Server
	if cfg.MetricsAddr != "" {
		// Deliberately its own listener, not a route on the public API
		// router: /metrics is an operational surface for Prometheus, not
		// something to expose to arbitrary API callers.
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", metrics.Handler())
		metricsSrv = &http.Server{
			Addr: cfg.MetricsAddr, Handler: metricsMux,
			ReadHeaderTimeout: cfg.HTTPReadHeaderTimeout, ReadTimeout: cfg.HTTPReadTimeout,
			WriteTimeout: cfg.HTTPWriteTimeout, IdleTimeout: cfg.HTTPIdleTimeout,
			MaxHeaderBytes: cfg.HTTPMaxHeaderBytes,
		}
		go func() {
			log.Printf("platform: metrics listening on %s", cfg.MetricsAddr)
			if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("platform: metrics server error: %v", err)
			}
		}()
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("platform: graceful shutdown error: %v", err)
		}
		if metricsSrv != nil {
			_ = metricsSrv.Shutdown(shutdownCtx)
		}
		if onShutdown != nil {
			onShutdown()
		}
	}()

	log.Printf("platform: listening on %s (%s)", cfg.HTTPAddr, chainLabel)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("platform: server error: %v", err)
	}
}

// runPlatform is main's entry point once config/repositories are ready:
// it seeds the single-tenant Project record Active straight from config
// (project.SeedProject — there is no on-chain factory to deploy from
// and observe), wires an App with no hot keys and no TxManager (the server
// only OBSERVES Solana events; every business program is provisioned
// independently and no wallet/relay ever broadcasts from this process — see
// the frozen solana-auth-contract and solana-chainevent-mapping docs),
// starts the indexer + reconciler ticker, and serves the same Gin API
// via serveHTTP. Because SeedProject makes the project Active
// immediately at startup, there is no rebuild-on-deploy step here — the
// router built once at startup is final for the process's lifetime.
func runPlatform(ctx context.Context, cfg config.Config, repos *repository.Repositories, mongoClient *mongodriver.Client) {
	client := blockchain.NewRPCClient(cfg.RPCURL)
	// Best-effort startup reachability check (there is no CHAIN_ID-style
	// numeric identity the RPC reports back to cross-check against — see
	// Config.ChainID's doc comment: it's a synthetic label this
	// deployment assigns for ChainEvent/IndexerCheckpoint scoping, not a
	// value getSlot/getHealth echo). Fail fast in production, log and
	// continue (retried by every background-loop tick) otherwise.
	// The `profile_digest` this deployment committed to on-chain at
	// `initialize`, read back by verifyVaultConfigOnChain below and handed to
	// SeedProject so the API can reject an Asset Profile that does not hash to
	// it (see project.SeedParams.ProfileDigest). It stays empty on every path
	// where the account could not be fully verified — an unreachable RPC, a
	// pre-`initialize` boot, or a cross-check failure — and SeedProject
	// deliberately treats empty as "leave whatever is already stored alone"
	// rather than clearing a digest a previous boot successfully read.
	var onChainProfileDigest string

	healthCtx, healthCancel := context.WithTimeout(ctx, 5*time.Second)
	_, healthErr := client.GetSlot(healthCtx, cfg.Commitment)
	healthCancel()
	if healthErr != nil {
		if cfg.Environment == config.EnvProduction {
			log.Fatalf("platform: RPC unavailable at startup (%v); refusing to start in production without a working RPC", healthErr)
		}
		log.Printf("platform: RPC unavailable at startup (%v); indexer loop will keep retrying", healthErr)
	} else {
		log.Printf("platform: connected to RPC at %s", cfg.RPCURL)
		// Cluster-identity cross-check: Solana has no
		// per-call chain-ID equivalent, but getGenesisHash returns a fixed
		// per-cluster identity value that this deployment's
		// chain.cluster_genesis already configures (it is also a domain
		// input to the mint-attestation digest — see
		// Config.ClusterGenesis's doc comment). Without this check a
		// devnet-vs-mainnet mixup, or any wrong CHAIN_RPC_URL, would go
		// fully undetected: the indexer would ingest the wrong cluster's
		// events and the compliance hot key would broadcast set_status to
		// the wrong cluster. Only attempted when the RPC was reachable
		// above; if it wasn't, production already fatal'd and development
		// is already retrying every background-loop tick.
		genesisCtx, genesisCancel := context.WithTimeout(ctx, 5*time.Second)
		genesisHash, genesisErr := client.GetGenesisHash(genesisCtx)
		genesisCancel()
		switch {
		case genesisErr != nil:
			if cfg.Environment == config.EnvProduction {
				log.Fatalf("platform: getGenesisHash unavailable at startup (%v); refusing to start in production without verifying cluster identity", genesisErr)
			}
			log.Printf("platform: getGenesisHash unavailable at startup (%v); cluster-identity check skipped", genesisErr)
		case genesisHash != cfg.ClusterGenesis:
			// Always fatal, in every environment: a wrong-cluster RPC is
			// never a legitimate configuration to silently degrade into.
			log.Fatalf("platform: RPC genesis hash %q does not match configured chain.cluster_genesis %q — refusing to start against the wrong cluster", genesisHash, cfg.ClusterGenesis)
		default:
			log.Printf("platform: verified cluster identity (genesis %s)", genesisHash)
		}

		// Boot-time cross-check: confirm the on-chain rwa-supply-controller Config
		// account's owner, Anchor discriminator, `vault` field, and
		// available domain fields (admin/token_mint/cluster) actually
		// match this deployment's configured values.
		// verifyVaultConfigOnChain itself never calls log.Fatalf; it
		// returns an ordinary error for EVERY "cannot verify" condition
		// (missing account, RPC failure, wrong owner, bad discriminator,
		// wrong size) as well as a genuine mismatch, leaving fatality to
		// this caller. In production, seeding the project Active on an
		// unverified supply-config account would let this instance
		// advertise a usable mint pipeline whose attestation domain cannot
		// be trusted to match what the on-chain program reconstructs — so
		// a verification failure is a startup failure there, unless the
		// operator has explicitly opted into a pre-initialization boot via
		// PRODUCTION_ALLOW_UNVERIFIED_SUPPLY_CONFIG. Outside
		// production this stays best-effort/non-fatal, exactly as before
		// (a fresh local deployment's supply-controller is routinely not
		// yet `initialize`d when the platform first boots).
		vaultCfgCtx, vaultCfgCancel := context.WithTimeout(ctx, 5*time.Second)
		verifiedProfileDigest, verifyErr := verifyVaultConfigOnChain(vaultCfgCtx, client, cfg)
		vaultCfgCancel()
		onChainProfileDigest = verifiedProfileDigest
		switch {
		case verifyErr == nil:
			// verifyVaultConfigOnChain already logged the success
			// details.
		case cfg.Environment == config.EnvProduction && !cfg.AllowUnverifiedSupplyConfig:
			log.Fatalf("platform: supply-controller Config cross-check failed (%v); refusing to seed the project Active in production without a fully verified account — set PRODUCTION_ALLOW_UNVERIFIED_SUPPLY_CONFIG=true to explicitly opt into a pre-initialization boot", verifyErr)
		case cfg.Environment == config.EnvProduction:
			log.Printf("platform: WARNING: supply-controller Config cross-check failed (%v) but PRODUCTION_ALLOW_UNVERIFIED_SUPPLY_CONFIG=true overrides the startup failure — proceeding with an UNVERIFIED supply-config account", verifyErr)
		default:
			log.Printf("platform: vault-config cross-check skipped (%v)", verifyErr)
		}
	}

	// Seed the Project record Active from config BEFORE building the App or
	// starting any reconciler — every reconciler + the API's GET /project
	// gate on Project.Status==Active (see SeedProject's doc comment).
	// Idempotent: safe to run on every boot.
	seedCtx, seedCancel := context.WithTimeout(ctx, 5*time.Second)
	seedErr := project.SeedProject(seedCtx, project.SeedParams{
		ChainID:                 cfg.ChainID,
		ProjectID:               cfg.ProjectID,
		RWAMint:                 cfg.RWAMint,
		QuoteMint:               cfg.QuoteMint,
		ProgramVault:            cfg.ProgramVault,
		ProgramCompliance:       cfg.ProgramCompliance,
		ProgramSupplyController: cfg.ProgramSupplyController,
		ProgramRedemption:       cfg.ProgramRedemption,
		ProgramPricing:          cfg.ProgramPricing,
		RWADecimals:             cfg.RWADecimals,
		QuoteDecimals:           cfg.QuoteDecimals,
		AdminPubkey:             cfg.AdminPubkey,
		ProfileDigest:           onChainProfileDigest,
	}, repos.Projects)
	seedCancel()
	if seedErr != nil {
		log.Fatalf("platform: seeding project: %v", seedErr)
	}

	app, providers := buildApp(cfg, repos, client, mongoClient, loadAuditorBaseline(ctx, repos))
	router := api.NewRouter(app)
	webui.Attach(router)

	bgCtx, cancel := context.WithCancel(ctx)
	startBackgroundLoops(bgCtx, cfg, repos, client, app)

	onShutdown := func() {
		cancel()
		for _, p := range providers {
			if err := p.Close(); err != nil {
				log.Printf("platform: closing key provider: %v", err)
			}
		}
	}
	serveHTTP(ctx, cfg, router, onShutdown, fmt.Sprintf("chainId=%d", cfg.ChainID))
}

// configAdminOffset/configTokenMintOffset/configVaultOffset/
// configClusterOffset (+ their matching *Len constants) locate fields
// within the rwa-supply-controller Config account's raw data, past the
// 8-byte Anchor account discriminator configDiscriminator checks
// separately. Verified against
// solana/programs/rwa-supply-controller/src/lib.rs's `Config` struct
// declaration:
//
//	pub struct Config {
//	    pub admin: Pubkey,          // 32 bytes, offset  8  <-- configAdminOffset
//	    pub pending_admin: Pubkey,  // 32 bytes, offset 40
//	    pub auditor_eth: [u8; 20],  // 20 bytes, offset 72
//	    pub token_mint: Pubkey,     // 32 bytes, offset 92  <-- configTokenMintOffset
//	    pub vault: Pubkey,          // 32 bytes, offset 124 <-- configVaultOffset
//	    pub registry: Pubkey,       // 32 bytes, offset 156
//	    pub profile_digest: [u8; 32],//32 bytes, offset 188
//	    pub cluster: [u8; 32],      // 32 bytes, offset 220 <-- configClusterOffset
//	    pub finalized: bool,
//	    pub bump: u8,
//	}
//
// Anchor's #[account] macro derives Borsh (de)serialization, which encodes
// struct fields strictly in DECLARATION order with no padding/alignment —
// unlike a C struct, there is no reordering or gap to account for, so
// summing preceding field sizes gives the exact byte offset. This is
// independently cross-checked by the same source file's own
// `Config::SPACE = 8+32+32+20+32+32+32+32+32+1+1` constant (used to
// allocate the account at `init`): its field-size sequence matches this
// comment's byte-for-byte, computed by a different person for a different
// purpose (rent-exempt sizing, not this cross-check) — two independent
// readings of the same struct agreeing is strong evidence the offsets are
// right. configAccountSize below is the total from that same SPACE
// constant, used as a defense-in-depth guard: if a future on-chain program
// upgrade ever changes Config's shape, an account that no longer matches
// this exact size trips THAT check before any offset could ever be read
// against the wrong bytes.
//
// registry, pending_admin, auditor_eth, finalized, and bump have no matching
// config value to cross-check against (registry/pending_admin/finalized/bump
// are not config inputs at all; auditor_eth is a live-rotatable authority, not
// a fixed deployment constant) — only admin/token_mint/vault/cluster are
// compared, and only admin when cfg.AdminPubkey is actually set (it is
// optional outside production — see Config.AdminPubkey's doc comment).
//
// profile_digest is the one field read for a purpose OTHER than cross-checking:
// it is not a config input either (the operator commits to it at bootstrap, in
// bootstrap.config.json), so there is nothing to compare it against here — but
// it IS the value every Asset Profile must hash to, so verifyVaultConfigOnChain
// returns it for project.SeedProject to persist. See Project.ProfileDigest.
const (
	configAdminOffset         = 8
	configAdminLen            = 32
	configTokenMintOffset     = 8 + 32 + 32 + 20 // = 92
	configTokenMintLen        = 32
	configVaultOffset         = 8 + 32 + 32 + 20 + 32 // = 124
	configVaultLen            = 32
	configProfileDigestOffset = 8 + 32 + 32 + 20 + 32 + 32 + 32 // = 188
	configProfileDigestLen    = 32
	configClusterOffset       = 8 + 32 + 32 + 20 + 32 + 32 + 32 + 32 // = 220
	configClusterLen          = 32
	configAccountSize         = 8 + 32 + 32 + 20 + 32 + 32 + 32 + 32 + 32 + 1 + 1 // = 254, Config::SPACE
)

// configDiscriminator is the Anchor account discriminator every
// genuine rwa-supply-controller Config account's first 8 bytes must equal —
// sha256("account:Config")[:8], the same scheme
// internal/blockchain/idl_test.go verifies this codebase's event
// discriminators against (there, the "event:" namespace; accounts use
// "account:" — see Anchor's discriminator derivation). Checking this is what
// actually rules out an unrelated account of coincidentally
// the right size and owner: byte length and owner alone don't prove the
// account is a Config, only its own program-declared discriminator does.
var configDiscriminator = func() [8]byte {
	sum := sha256.Sum256([]byte("account:Config"))
	var d [8]byte
	copy(d[:], sum[:8])
	return d
}()

// verifyVaultConfigOnChain reads the rwa-supply-controller Config
// account at cfg.SupplyConfig over RPC and confirms it is genuinely a
// Config account belonging to the configured supply-controller program, and
// that its `vault` field (plus every other available domain field) matches
// this deployment's configuration: a wrong `vault` value means every
// mint attestation this process builds is unsignable/rejected on-chain (see
// Config.VaultConfig's doc comment), and an earlier version of this check
// — byte length plus one fixed-offset field only — could be satisfied by an
// unrelated 254-byte account with chosen bytes at the vault offset, since
// GetAccountInfo used to discard the account's owner entirely and never
// checked the Anchor discriminator.
//
// This function NEVER calls log.Fatalf itself —
// EVERY failure mode (RPC error, missing account, wrong owner, wrong size,
// bad discriminator, or a genuine field mismatch) returns an ordinary,
// non-nil error and leaves fatality entirely to the caller (runPlatform),
// which applies different policy in production vs. development (see its
// call site's doc comment) — a policy decision this low-level account-
// reading helper has no business making itself.
// On success it also returns the account's `profile_digest` as a 0x-prefixed
// lowercase hex string — the digest the deployment permanently committed to at
// `initialize`. It is returned only on the fully-verified path so a caller can
// never persist a digest read out of an account whose owner/discriminator/size
// were not proven first; on any error the returned string is empty.
func verifyVaultConfigOnChain(ctx context.Context, client *blockchain.RPCClient, cfg config.Config) (string, error) {
	info, err := client.GetAccountInfo(ctx, cfg.SupplyConfig, cfg.Commitment)
	if err != nil {
		return "", fmt.Errorf("reading supply-controller config account %s: %w", cfg.SupplyConfig, err)
	}
	if info == nil {
		return "", fmt.Errorf("supply-controller config account %s does not exist yet (not initialized)", cfg.SupplyConfig)
	}
	// Owner check FIRST: an account merely resembling a
	// Config in size/bytes but owned by some other program can never
	// genuinely be this deployment's supply-controller Config, regardless
	// of what its data contains.
	if info.Owner != cfg.ProgramSupplyController {
		return "", fmt.Errorf("supply-controller config account %s is owned by program %q, want the configured supply-controller program %q — this account cannot be a genuine Config for this deployment", cfg.SupplyConfig, info.Owner, cfg.ProgramSupplyController)
	}
	data := info.Data
	// Exact-size guard (defense-in-depth, see configAccountSize's doc
	// comment): trust the byte-offset reads below only when the account is
	// PRECISELY the size the current on-chain program layout produces. A
	// mismatched size — too short, too long, or otherwise unexpected — means
	// this process's assumption about the account's shape may be stale (a
	// program upgrade, a wrong address, or a decode bug), so this returns a
	// non-fatal "cannot verify" error rather than risk comparing bytes that
	// don't actually mean what the offset constants above assume they mean.
	if len(data) != configAccountSize {
		return "", fmt.Errorf("supply-controller config account %s is %d bytes, want exactly %d (Config::SPACE) — the on-chain account shape may not match this process's layout assumption; skipping the cross-check rather than trusting a possibly-wrong byte offset", cfg.SupplyConfig, len(data), configAccountSize)
	}
	// Anchor account discriminator: the check the exact-size
	// guard alone cannot make — an unrelated account happening to also be
	// exactly 254 bytes and owned by this same program (e.g. a different
	// account type this program declares) is ruled out here.
	if !bytes.Equal(data[:8], configDiscriminator[:]) {
		return "", fmt.Errorf("supply-controller config account %s has discriminator %x, want the Anchor Config account discriminator %x — this account's type does not match Config", cfg.SupplyConfig, data[:8], configDiscriminator)
	}

	onChainVault := base58.Encode(data[configVaultOffset : configVaultOffset+configVaultLen])
	if onChainVault != cfg.VaultConfig {
		return "", fmt.Errorf("on-chain supply-controller Config.vault %q does not match configured contract.vault_config %q — every Solana mint attestation this process builds would be unsignable/rejected on-chain", onChainVault, cfg.VaultConfig)
	}
	// Additional domain-field cross-checks: compare
	// every OTHER field this account carries that also has a known-good
	// config value to compare against, so a look-alike account sharing only
	// the right owner/discriminator/size/vault still can't satisfy the
	// check. Gated on the config value actually being set — token_mint and
	// cluster are always required (see config.Load), but this function is
	// also exercised directly (tests, and a caller that hands it a
	// partially-populated config) against a live account that may
	// legitimately not have every optional field populated yet.
	if cfg.RWAMint != "" {
		onChainMint := base58.Encode(data[configTokenMintOffset : configTokenMintOffset+configTokenMintLen])
		if onChainMint != cfg.RWAMint {
			return "", fmt.Errorf("on-chain supply-controller Config.token_mint %q does not match configured contract.rwa_mint %q", onChainMint, cfg.RWAMint)
		}
	}
	if cfg.ClusterGenesis != "" {
		onChainCluster := base58.Encode(data[configClusterOffset : configClusterOffset+configClusterLen])
		if onChainCluster != cfg.ClusterGenesis {
			return "", fmt.Errorf("on-chain supply-controller Config.cluster %q does not match configured chain.cluster_genesis %q", onChainCluster, cfg.ClusterGenesis)
		}
	}
	if cfg.AdminPubkey != "" {
		onChainAdmin := base58.Encode(data[configAdminOffset : configAdminOffset+configAdminLen])
		if onChainAdmin != cfg.AdminPubkey {
			return "", fmt.Errorf("on-chain supply-controller Config.admin %q does not match configured security.admin_pubkey %q", onChainAdmin, cfg.AdminPubkey)
		}
	}
	// profile_digest is read (not compared — it has no config counterpart)
	// only now that owner, discriminator, size, and every comparable domain
	// field have been proven, so the bytes at this offset are known to belong
	// to a genuine Config for this deployment.
	profileDigest := "0x" + hex.EncodeToString(data[configProfileDigestOffset:configProfileDigestOffset+configProfileDigestLen])
	log.Printf("platform: verified supply-controller Config account %s (owner, discriminator, vault=%s, and available domain fields all match; on-chain profile_digest=%s)", cfg.SupplyConfig, onChainVault, profileDigest)
	return profileDigest, nil
}

// loadAuditorBaseline reads the best already-known auditor address for
// a fresh assets.NewRecordService to start from. There is no
// deploy-time capture — SeedProject never sets Project.Auditor (there
// is no factory/deploy request carrying one to capture) — so the best
// available value is the live event-sourced projection
// (Project.Security.Auditor), if a previous process run already reconciled
// one; the zero address otherwise. Either way this is only a starting
// point: startBackgroundLoops' 5s ReconcileAuditor tick keeps it
// current from here on (see RecordService.SetAuditor).
func loadAuditorBaseline(ctx context.Context, repos *repository.Repositories) common.Address {
	p, err := repos.Projects.Get(ctx)
	if err != nil {
		return common.Address{}
	}
	if p.Security != nil && p.Security.Auditor != "" {
		return common.HexToAddress(p.Security.Auditor)
	}
	return common.HexToAddress(p.Auditor)
}

// buildApp wires the App: chain-independent app construction (audit log,
// investor/admin wallet-auth challenges — using the ed25519 auth.Verifier —
// session manager, KYC provider/webhook wiring) plus bootstrap values, a
// ReadyCheck/LastIndexedBlock, read-only Redemptions/Sales services so the
// indexed read models are actually served (see redemption.New/sales.New
// below), a Records service (assets.NewRecordService)
// so createRecord/reissueRecord work — see auditorBaseline's doc comment and
// loadAuditorBaseline for where its starting auditor comes from — and,
// when security.compliance_key is configured, a Status service
// (compliance.StatusService) so POST /compliance/status and the
// KYC-webhook auto-allowlist path (driven by startBackgroundLoops'
// WebhookReconciler ticker) work too: this server's ONE hot key
// signs and broadcasts rwa-compliance set_status instructions — the
// deliberate exception to "the server only observes on-chain events" that the
// user explicitly approved.
//
// V1 read/write limitations that remain (deliberate, not oversights):
//   - GET /sales/inventory always 501s (see api.getInventory): live Vault/
//     mint balances need a chain client this process never holds; the SPA
//     reads them directly via web3.js instead.
//   - GET /transactions is always empty: there is no on-chain-transaction
//     indexer yet.
//   - Compliance status writes have no confirmation-depth polling — see
//     StatusService's doc comment for the optimistic-Confirmed model
//     this uses instead.
//   - security.compliance_key only supports "raw" key material (inline
//     base58 or a plaintext keypair file) — no local-keystore/vault/
//     kms-mock custody yet; see loadComplianceKey's doc comment.
//
// downloadPackage (BuildPackage) works too (the D2
// pass) — assets.RecordService.BuildPackage delegates to buildPackage,
// which embeds a Solana-shaped typed-data.json (see
// assets.RecordService.buildPackage), reusing this pass's
// BuildMintAttestation for the digest.
// It deliberately wires NO Project service — Project is seeded directly by
// SeedProject (runPlatform). There are no keys.Provider
// instances in this pass — the compliance signer's raw
// ed25519.PrivateKey bytes are held directly by the StatusService
// closure rather than through the keys.Provider abstraction (see
// loadComplianceKey), so they are NOT explicitly zeroed at shutdown
// the way a keys.Provider-backed key is — a real, flagged gap (Go's GC will
// eventually reclaim the memory, but that's not the same guarantee
// keys.Provider.Close() makes). The returned slice always holds at most the
// one complianceKeyCloser registered below.
func buildApp(cfg config.Config, repos *repository.Repositories, client *blockchain.RPCClient, mongoClient *mongodriver.Client, auditorBaseline common.Address) (*api.App, []keys.Provider) {
	var providers []keys.Provider
	app := &api.App{
		Repos:                   repos,
		ProjectID:               cfg.ProjectID,
		ChainID:                 cfg.ChainID,
		ProgramCompliance:       cfg.ProgramCompliance,
		ProgramVault:            cfg.ProgramVault,
		ProgramPricing:          cfg.ProgramPricing,
		ProgramTransferHook:     cfg.ProgramTransferHook,
		ProgramRedemption:       cfg.ProgramRedemption,
		ProgramSupplyController: cfg.ProgramSupplyController,
		RWAMint:                 cfg.RWAMint,
		QuoteMint:               cfg.QuoteMint,
		ClusterGenesis:          cfg.ClusterGenesis,
		SupplyConfig:            cfg.SupplyConfig,
		VaultConfig:             cfg.VaultConfig,
		MaxCheckpointAge:        cfg.MaxCheckpointAge,
		AdminAddress:            cfg.AdminPubkey,
		JWTSecret:               []byte(cfg.JWTSecret),
		JWTTTL:                  cfg.JWTTTL,
		IdempotencyTTL:          cfg.IdempotencyTTL,
		RateLimitRPS:            cfg.RateLimitRPS,
		RateLimitBurst:          cfg.RateLimitBurst,
		CORSAllowedOrigins:      cfg.CORSAllowedOrigins,
		MaxRequestBodyBytes:     cfg.MaxRequestBodyBytes,
		TrustedProxies:          cfg.TrustedProxies,
	}
	app.Audit = auditlog.New(repos.AuditLogs)

	verifier := auth.NewVerifier()
	app.Challenges = compliance.NewChallengeService(repos.WalletChallenges, repos.Investors, cfg.WalletChallengeTTL, "RWA Platform", verifier)
	app.Sessions = auth.NewSessionManager(repos.WalletSessions, cfg.WalletSessionTTL)
	app.AdminChallenges = auth.NewAdminChallengeService(repos.AdminChallenges, cfg.WalletChallengeTTL, "RWA Platform", verifier)

	// Both services are reads-only over the indexed repositories
	// (List/ListPage/Get, ListPurchases) — the server never builds or
	// broadcasts a sale/redemption transaction, so neither needs a chain
	// client. Beneficiary compliance lookups go to the indexed investor
	// record instead (see api.App.beneficiaryAllowed in
	// internal/api/redemptions.go).
	app.Redemptions = redemption.New(repos.RedemptionRequests)
	app.Sales = sales.New(repos.Purchases)

	// Prefer a ReplicationManager when a backup destination is configured,
	// else the bare local Kubo client, else nil — CreateRecord's pin
	// becomes a no-op when nil.
	var ipfsClient interface {
		AddRaw(ctx context.Context, data []byte) (string, error)
	}
	if cfg.IPFSAPIURL != "" {
		local := ipfs.NewKuboClient(cfg.IPFSAPIURL)
		if rm := newIPFSReplicationManager(cfg, local, repos); rm != nil {
			ipfsClient = rm
		} else {
			ipfsClient = local
		}
	}
	records, recErr := assets.NewRecordService(
		repos.AssetRecords, repos.AuditPackages, repos.Attestations, ipfsClient,
		// The mint attestation's `vault` field is the rwa-vault Config
		// PDA (cfg.VaultConfig), NOT the vault program id
		// (cfg.ProgramVault) — see Config.VaultConfig's doc
		// comment and verifyVaultConfigOnChain below.
		cfg.ClusterGenesis, cfg.ProgramSupplyController, cfg.SupplyConfig, cfg.VaultConfig,
		auditorBaseline,
	)
	if recErr != nil {
		// config.Load already base58-validates every one of these fields,
		// so this is unreachable in practice — degrade rather than crash
		// the whole process on a defensive check that should never fire.
		log.Printf("platform: record service not configured (%v); asset record endpoints disabled", recErr)
	} else {
		app.Records = records
	}

	kycProvider, kerr := kyc.New(kyc.Config{
		Mode:              kyc.Mode(cfg.KYCProvider),
		GenericHMACSecret: cfg.KYCWebhookHMACSecret,
		Sumsub: kyc.SumsubConfig{
			AppToken: cfg.KYCSumsubAppToken, SecretKey: cfg.KYCSumsubSecretKey,
			WebhookSecret: cfg.KYCSumsubWebhookSecret, BaseURL: cfg.KYCSumsubBaseURL, LevelName: cfg.KYCSumsubLevelName,
		},
		Onfido: kyc.OnfidoConfig{
			APIToken: cfg.KYCOnfidoAPIToken, WebhookToken: cfg.KYCOnfidoWebhookToken,
			Region: cfg.KYCOnfidoRegion, WorkflowID: cfg.KYCOnfidoWorkflowID, Referrer: cfg.KYCOnfidoReferrer,
		},
	})
	if kerr != nil {
		log.Printf("platform: KYC provider not configured (%v); KYC endpoints disabled", kerr)
	} else if kycProvider != nil {
		app.KYC = kycProvider
		app.Webhooks = compliance.NewWebhookService(repos.KYCEvents, repos.Investors, cfg.KYCWebhookHMACSecret)
	}

	// Compliance status writes (POST /compliance/status, the KYC-webhook
	// auto-allowlist path — see startBackgroundLoops' WebhookReconciler
	// ticker) — optional: an unset security.compliance_key just leaves
	// app.Status nil (both paths 501/no-op), not a startup failure.
	if cfg.ComplianceKey != "" {
		signer, err := loadComplianceKey(cfg.ComplianceKey)
		if err != nil {
			log.Printf("platform: compliance key not configured (%v); compliance status writes disabled", err)
		} else if statusSvc, err := compliance.NewStatusService(client, repos.Transactions, cfg.ProgramCompliance, signer, cfg.Commitment); err != nil {
			log.Printf("platform: compliance status service not configured (%v); compliance status writes disabled", err)
		} else {
			app.Status = statusSvc
			// Registered so onShutdown's providers loop actually zeroes
			// this key's in-memory bytes at process shutdown.
			providers = append(providers, &complianceKeyCloser{key: signer})
			log.Printf("platform: compliance authority pubkey: %s", statusSvc.PublicKey())
			// Best-effort boot-time cross-check against whatever the security
			// projector has already reconciled from a previous run. A
			// brand-new deployment with no prior reconcile has nothing to
			// compare against yet, which is not itself a problem — the
			// operator configured this key deliberately.
			if p, err := repos.Projects.Get(context.Background()); err == nil && p.Security != nil && p.Security.ComplianceOperator != "" {
				if p.Security.ComplianceOperator != statusSvc.PublicKey() {
					log.Printf("platform: WARNING: configured security.compliance_key pubkey %s does not match the on-chain compliance authority %s — set_status calls will be rejected until this is corrected", statusSvc.PublicKey(), p.Security.ComplianceOperator)
				}
			}
		}
	}

	app.ReadyCheck = func() error {
		rpcCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := client.GetSlot(rpcCtx, cfg.Commitment); err != nil {
			return fmt.Errorf("solana rpc: %w", err)
		}
		// Re-verify cluster identity on EVERY readiness probe, not just at
		// startup: an RPC endpoint that is repointed/
		// failed-over to a different cluster after boot must flip this
		// instance to not_ready before it indexes or signs against the
		// wrong network. Genesis is immutable per cluster, so this adds
		// one more RPC round trip per probe, not a cache.
		genesisCtx, genesisCancel := context.WithTimeout(context.Background(), 5*time.Second)
		h, err := client.GetGenesisHash(genesisCtx)
		genesisCancel()
		if err != nil {
			return fmt.Errorf("solana rpc genesis: %w", err)
		}
		if h != cfg.ClusterGenesis {
			return fmt.Errorf("solana rpc genesis %q != configured chain.cluster_genesis %q", h, cfg.ClusterGenesis)
		}
		// Fail readiness while the compliance program's INDEXER POLL HEALTH
		// is stale — see
		// complianceReadinessCheck's doc comment for the full
		// reasoning (measures LastSuccessfulPollAt, not UpdatedAt, and
		// fails on "never polled yet" too).
		if err := complianceReadinessCheck(context.Background(), repos, cfg); err != nil {
			return err
		}
		if mongoClient != nil {
			if err := mongoClient.Ping(context.Background(), nil); err != nil {
				return fmt.Errorf("storage: %w", err)
			}
		}
		return nil
	}
	// LastIndexedBlock has no single checkpoint — each of the 5
	// event-emitting programs pages its own getSignaturesForAddress history
	// independently (see internal/blockchain/checkpoint.go), so this
	// reports the LOWEST of their slots: the most-behind program is what
	// actually bounds how current the read models derived from ALL of them
	// can be.
	app.LastIndexedBlock = func() uint64 { return lastIndexedSlot(cfg, repos) }

	return app, providers
}

// complianceKeyCloser wraps the server's compliance ed25519 hot
// key in the keys.Provider interface purely so it can be zeroed at process
// shutdown. compliance.StatusService holds and signs
// with the raw ed25519.PrivateKey directly, never through this type — this
// wrapper exists only so onShutdown's provider loop can Close() it.
type complianceKeyCloser struct {
	key ed25519.PrivateKey
}

// Reload is a no-op: this wrapper holds the key bytes it was constructed
// with and has no source to re-read them from (the operator supplies the
// keypair once at startup via security.compliance_key). It exists only to
// satisfy keys.Provider.
func (c *complianceKeyCloser) Reload(ctx context.Context) error { return nil }

// Close zeroes the key's in-memory bytes — best-effort (the Go runtime may
// have copied the bytes elsewhere via GC or stack growth before this runs).
func (c *complianceKeyCloser) Close() error {
	for i := range c.key {
		c.key[i] = 0
	}
	return nil
}

// complianceReadinessCheck reports whether the compliance program's
// indexer poll health is fresh enough for GET /health to report ready.
// Extracted as its own function
// (mirroring lastIndexedSlot just below) purely so it is unit
// testable independent of the RPC-dialing closures around it in
// buildApp's app.ReadyCheck.
//
// This measures models.IndexerCheckpoint.LastSuccessfulPollAt — the
// dedicated poll-HEALTH heartbeat blockchain.Indexer.pollProgram now writes on
// EVERY successful poll, including one that ingests zero signatures — NOT
// UpdatedAt, which only advances when the signature cursor itself moves.
// The old version of this check used UpdatedAt, which meant an idle but
// perfectly healthy compliance program (nothing to index) would fail
// readiness five minutes after its last on-chain event, while a program
// whose indexer had never completed even one successful poll (ErrNotFound
// silently ignored) reported ready. Both are fixed here:
//   - repository.ErrNotFound (no checkpoint row at all — the indexer has
//     never run) is now a not-ready condition, not silently skipped.
//   - A checkpoint row that exists but has a zero LastSuccessfulPollAt
//     (e.g. mid-backfill on a first sync, before that heartbeat existed on
//     an old row, or any other state that hasn't completed a successful
//     poll yet) is likewise not-ready.
//   - Any OTHER repository error (a genuine storage failure, not "doesn't
//     exist") is surfaced as not-ready rather than ignored.
//   - Staleness is measured against LastSuccessfulPollAt, so a healthy,
//     idle program stays ready indefinitely.
func complianceReadinessCheck(ctx context.Context, repos *repository.Repositories, cfg config.Config) error {
	if cfg.ProgramCompliance == "" {
		return nil
	}
	cp, err := repos.IndexerCheckpoints.Get(ctx, cfg.ChainID, cfg.ProgramCompliance)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		return fmt.Errorf("solana indexer: compliance program has not completed its first poll yet")
	case err != nil:
		return fmt.Errorf("solana indexer: compliance checkpoint lookup: %w", err)
	case cp.LastSuccessfulPollAt.IsZero():
		return fmt.Errorf("solana indexer: compliance checkpoint exists but has never recorded a successful poll")
	}
	if age := time.Since(cp.LastSuccessfulPollAt); age > cfg.MaxCheckpointAge {
		return fmt.Errorf("solana indexer: compliance poll heartbeat is %s old, exceeding chain.max_checkpoint_age (%s); indexer may be wedged", age.Round(time.Second), cfg.MaxCheckpointAge)
	}
	return nil
}

// lastIndexedSlot returns the lowest LastBlock (slot) across every
// configured program's IndexerCheckpoint, or 0 if any configured
// program has not completed a poll yet — see buildApp's
// LastIndexedBlock doc comment.
//
// The old version skipped ANY program whose checkpoint lookup errored
// (repository.ErrNotFound for a never-polled program, or a genuine storage
// failure — both `continue`d identically), so the reported minimum was
// only ever taken across the programs that DID have a row: a height none
// of the deployment's configured programs have collectively reached,
// feeding redemption.Confirmations/Claimable and the reported indexer
// height with a number that overstates how current the read model actually
// is. securityWatermark already gets this right
// (returns 0 unless every configured program has a row+heartbeat); this
// now matches it: a never-polled program (ErrNotFound) forces 0, and a
// genuine repository error is logged (not silently swallowed) before also
// failing this call closed to 0.
func lastIndexedSlot(cfg config.Config, repos *repository.Repositories) uint64 {
	programIDs := []string{
		cfg.ProgramCompliance, cfg.ProgramVault, cfg.ProgramPricing,
		cfg.ProgramRedemption, cfg.ProgramSupplyController,
	}
	var min uint64
	have := false
	for _, pid := range programIDs {
		if pid == "" {
			continue
		}
		cp, err := repos.IndexerCheckpoints.Get(context.Background(), cfg.ChainID, pid)
		switch {
		case errors.Is(err, repository.ErrNotFound):
			return 0
		case err != nil:
			log.Printf("platform: last-indexed-slot: load checkpoint for %s: %v", pid, err)
			return 0
		}
		if !have || cp.LastBlock < min {
			min = cp.LastBlock
			have = true
		}
	}
	return min
}

// startBackgroundLoops runs the indexer poll and every
// downstream reconciler (security/governance projection, the supply-
// controller auditor/minted projections, compliance, redemption, sales) on
// one shared 5s ticker, plus — when app.Webhooks is wired — a 10s
// WebhookReconciler ticker, so a KYC decision durably Accepted by
// app.Webhooks gets driven all the way to an on-chain set_status call and
// Applied (see app.Status, wired in buildApp only when
// security.compliance_key is configured; WebhookReconciler itself already
// treats a nil status as "durably accept, never apply" — see its submit doc
// comment — so this ticker is safe to run unconditionally whenever webhook
// ingestion is enabled at all). The indexer/reconcile tickers below are NOT
// gated by an indexer-safety check: the indexer has no reorg
// handling at all (every RPC call is made at a fixed commitment, normally
// "finalized", so results are by construction never rolled back — see
// internal/blockchain.Indexer's doc comment), so there is no
// ReconciliationRequired state to guard against here.
func startBackgroundLoops(ctx context.Context, cfg config.Config, repos *repository.Repositories, client *blockchain.RPCClient, app *api.App) {
	programIDs := map[blockchain.ProgramRole]string{
		blockchain.RoleCompliance:       cfg.ProgramCompliance,
		blockchain.RoleVault:            cfg.ProgramVault,
		blockchain.RolePricing:          cfg.ProgramPricing,
		blockchain.RoleRedemption:       cfg.ProgramRedemption,
		blockchain.RoleSupplyController: cfg.ProgramSupplyController,
	}
	idx := blockchain.New(client, repos.IndexerCheckpoints, repos.ChainEvents, programIDs, cfg.ChainID, cfg.Commitment, cfg.StartSlot)

	securityAddrs := project.ProgramAddrs{
		Vault: cfg.ProgramVault, Compliance: cfg.ProgramCompliance,
		SupplyController: cfg.ProgramSupplyController, RedemptionEscrow: cfg.ProgramRedemption,
		Pricing: cfg.ProgramPricing,
	}

	// A standalone RecordService used ONLY for the two supply-controller
	// projections below (ReconcileAuditor/ReconcileMinted read
	// only chain_events + repos.AssetRecords and write s.auditor/
	// AssetRecord.Status — see internal/assets/projector.go). It is built
	// separately from app.Records rather than reusing it because app.Records
	// is nil whenever the record endpoints are disabled, and these
	// projections must still run. It needs no IPFS pinner (projections never
	// publish) and no auditor baseline (ReconcileAuditor is what
	// establishes it from chain events).
	// Prefer app.Records: it is the instance the API builds .rwa packages with,
	// and ReconcileAuditor/SetBaselineAuditor must update THAT one. Running the
	// projections against a separate instance (as this used to) meant the
	// auditor baked into every package stayed frozen at process start — a
	// server booted before the chain was bootstrapped emitted zero-auditor,
	// unsignable packages for its whole lifetime, and even a genuine on-chain
	// auditor rotation never reached them. The standalone fallback below exists
	// only for the case app.Records is nil (record endpoints disabled), where
	// the projections must still run.
	records := app.Records
	var recErr error
	if records == nil {
		records, recErr = assets.NewRecordService(repos.AssetRecords, repos.AuditPackages, repos.Attestations, nil,
			cfg.ClusterGenesis, cfg.ProgramSupplyController, cfg.SupplyConfig, cfg.VaultConfig,
			common.Address{})
	}
	if recErr != nil {
		// Degrade to "these two projections are off", NOT "the indexer is
		// off". This used to skip starting the ticker entirely, which meant a
		// single RecordService construction failure silently disabled
		// idx.Poll and EVERY reconciler with it: no chain_events would ever be
		// written, every checkpoint would sit at lastBlock 0, and every read
		// model (compliance, purchases, redemptions, security) would stay
		// empty — with one log line as the only symptom. records is nil-safe
		// in pollAndReconcile below.
		log.Printf("platform: supply-controller projections disabled (%v) — indexing and every other reconciler still run", recErr)
		records = nil
	}
	go runTicker(ctx, 5*time.Second, func() {
		pollAndReconcile(ctx, cfg, repos, client, idx, records, securityAddrs)
	})

	// Drive Accepted->Applying->Applied/Failed for durably queued webhook
	// decisions — see this function's doc comment for why it's safe to run
	// even when app.Status is nil (webhook ingestion enabled, no
	// security.compliance_key configured).
	if app.Webhooks != nil {
		webhookReconciler := compliance.NewWebhookReconciler(repos.KYCEvents, repos.Transactions, app.Status)
		if err := webhookReconciler.Reconcile(ctx); err != nil {
			log.Printf("platform: webhook reconcile error: %v", err)
		}
		go runTicker(ctx, 10*time.Second, func() {
			if err := webhookReconciler.Reconcile(ctx); err != nil {
				log.Printf("platform: webhook reconcile error: %v", err)
			}
		})
	}
}

// readSecurityBaseline reads the programs' config accounts and adapts them to
// the projection's baseline input.
//
// It never fails the caller: a partial or entirely-empty baseline is a valid
// result (mid-bootstrap, RPC hiccup), and project.foldSecurity treats an unset
// field as "no baseline for this field" — so the worst case is the old
// event-only projection, never a wrong or blanked value. Errors are logged
// once per tick at most, since they are expected to be routine before the
// deployment is bootstrapped.
//
// The timeout is deliberately short and separate from the tick's own context:
// five getAccountInfo calls on a slow RPC must not delay the reconcilers that
// run after this one in pollAndReconcile.
func readSecurityBaseline(ctx context.Context, cfg config.Config, client *blockchain.RPCClient) project.SecurityBaseline {
	baselineCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	b, err := blockchain.ReadBaseline(baselineCtx, client, blockchain.BaselinePrograms{
		SupplyController: cfg.ProgramSupplyController,
		SupplyConfig:     cfg.SupplyConfig,
		Vault:            cfg.ProgramVault,
		VaultConfig:      cfg.VaultConfig,
		Pricing:          cfg.ProgramPricing,
		Compliance:       cfg.ProgramCompliance,
		Redemption:       cfg.ProgramRedemption,
	}, cfg.Commitment)
	if err != nil {
		log.Printf("platform: reading on-chain security baseline (partial results still applied): %v", err)
	}
	return project.SecurityBaseline{
		Auditor:                      b.Auditor,
		Treasury:                     b.Treasury,
		Treasurer:                    b.Treasurer,
		Pricer:                       b.Pricer,
		ComplianceOperator:           b.ComplianceOperator,
		Pauser:                       b.Pauser,
		RedemptionManager:            b.RedemptionManager,
		PurchasePricePerWholeToken:   b.PurchasePricePerWholeToken,
		RedemptionPricePerWholeToken: b.RedemptionPricePerWholeToken,
		Paused:                       b.Paused,
		// Admin is deliberately left unset: project.ReconcileSecurity falls
		// back to the config-seeded Project.Admin, which is the existing
		// (already-working) admin baseline.
	}
}

// pollAndReconcile is startBackgroundLoops' 5s-ticker body,
// factored out into its own named function purely so it is directly
// testable independent of runTicker's goroutine/timer
// plumbing.
//
// idx.Poll already attempts every configured program and joins their errors
// (see Indexer.Poll's doc comment) — a persistent failure for ONE program
// must not suppress every OTHER program's downstream reconciler. The old
// code returned immediately on any joined error, which silently froze the
// security/auditor/minted/compliance/redemption/sales projections for
// EVERY program whenever even one was unavailable (e.g. a single
// permanently-pruned/unavailable getTransaction response for one
// compliance-referencing signature), even though the other programs'
// events were indexed and checkpointed just fine this same tick. Every
// reconciler below is a full replay over already-persisted,
// already-checkpointed chain_events — safe to rerun regardless of whether
// idx.Poll's error names an unrelated program — so this now always runs
// every reconciler, logging (not returning on) idx.Poll's error.
func pollAndReconcile(ctx context.Context, cfg config.Config, repos *repository.Repositories, client *blockchain.RPCClient, idx *blockchain.Indexer, records *assets.RecordService, securityAddrs project.ProgramAddrs) {
	if err := idx.Poll(ctx); err != nil {
		log.Printf("platform: indexer poll error: %v", err)
	}
	// Read the config accounts EVERY tick rather than once at boot. The
	// accounts routinely do not exist on the first passes — the sanctioned
	// pre-bootstrap boot (operator-guide §3) starts the platform before
	// `initialize` has ever run — so a one-shot read would leave the whole
	// security projection empty until somebody happened to restart the
	// process. Failures are logged and the (possibly partial) baseline is
	// still used: an unreadable account contributes no fields, which degrades
	// exactly to the old event-only behaviour rather than blanking anything.
	baseline := readSecurityBaseline(ctx, cfg, client)
	if err := project.ReconcileSecurity(ctx, repos.Projects, repos.ChainEvents, repos.IndexerCheckpoints, cfg.ChainID, securityAddrs, baseline); err != nil {
		log.Printf("platform: security reconcile error: %v", err)
	}
	// Feed the on-chain auditor into the service that builds .rwa packages.
	// It is read from the supply-controller's config account, which is the ONLY
	// place it exists for a deployment that has never rotated — `initialize`
	// emits no event, so ReconcileAuditor below would otherwise fall back to
	// the (possibly zero) value loaded at process start forever.
	if records != nil && baseline.Auditor != "" && common.IsHexAddress(baseline.Auditor) {
		records.SetBaselineAuditor(common.HexToAddress(baseline.Auditor))
	}
	// records is nil when NewRecordService failed at startup — only these two
	// projections are lost, never the poll or the other reconcilers.
	if cfg.ProgramSupplyController != "" && records != nil {
		if err := records.ReconcileAuditor(ctx, repos.ChainEvents, cfg.ChainID, cfg.ProgramSupplyController); err != nil {
			log.Printf("platform: auditor reconcile error: %v", err)
		}
		if err := records.ReconcileMinted(ctx, repos.ChainEvents, cfg.ChainID, cfg.ProgramSupplyController, repos.AssetRecords); err != nil {
			log.Printf("platform: minted reconcile error: %v", err)
		}
	}
	if cfg.ProgramCompliance != "" {
		// compliance.Reconcile: the on-chain registry emits newStatus as
		// a uint and newValidUntil as a decimal string — Reconcile
		// pre-adapts both before reusing BuildStatuses + the shared
		// persistence loop.
		if err := compliance.Reconcile(ctx, repos.ChainEvents, cfg.ChainID, cfg.ProgramCompliance, repos.Investors); err != nil {
			log.Printf("platform: compliance reconcile error: %v", err)
		}
	}
	if cfg.ProgramRedemption != "" {
		if err := redemption.Reconcile(ctx, repos.ChainEvents, cfg.ChainID, cfg.ProgramRedemption, cfg.RedemptionTimeout, repos.RedemptionRequests); err != nil {
			log.Printf("platform: redemption reconcile error: %v", err)
		}
	}
	if cfg.ProgramVault != "" {
		if err := sales.Reconcile(ctx, repos.ChainEvents, cfg.ChainID, cfg.ProgramVault, repos.Purchases); err != nil {
			log.Printf("platform: sales reconcile error: %v", err)
		}
	}
	// Last, and program-agnostic: every wallet-broadcast action across ALL
	// programs becomes a Transaction row. Without it GET /transactions only
	// ever shows this server's own compliance writes, since nothing else it
	// displays is submitted by the server at all.
	if err := txindex.Reconcile(ctx, repos.Transactions, repos.ChainEvents, cfg.ChainID); err != nil {
		log.Printf("platform: transaction index reconcile error: %v", err)
	}
}

// routerHandler lets the public HTTP listener's *gin.Engine be swapped
// atomically, so a future rebuild-on-reconfigure step can replace the
// active router without a server restart. Not currently wired into
// runPlatform — SeedProject makes the project Active immediately
// at startup, so the router built once at startup is already final for the
// process's lifetime — but kept available as chain-neutral machinery.
type routerHandler struct{ p atomic.Pointer[gin.Engine] }

func (h *routerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.p.Load().ServeHTTP(w, r) }
func (h *routerHandler) set(r *gin.Engine)                                { h.p.Store(r) }

// providerRegistry tracks every keys.Provider created over the process's
// lifetime so shutdown can zero every hot key's in-memory material exactly
// once each. Not currently wired into runPlatform (its own
// onShutdown closure iterates the one-time providers slice directly), but
// kept available as chain-neutral machinery for a future multi-rebuild path.
type providerRegistry struct {
	mu        sync.Mutex
	providers []keys.Provider
}

func (r *providerRegistry) add(ps []keys.Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers = append(r.providers, ps...)
}

func (r *providerRegistry) closeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.providers {
		if err := p.Close(); err != nil {
			log.Printf("platform: closing key provider: %v", err)
		}
	}
}

// connectRepositories resolves the persistence backend per
// cfg.PersistenceMode. The persistence mode is explicit; in-memory
// repositories are only permitted behind a development/test flag.
//
// PersistenceMode=="memory" is an explicit, intentional opt-in (config.Load
// refuses it in EnvProduction) — `go run ./cmd/platform` and local smoke
// tests can request it directly instead of relying on a silent fallback.
//
// PersistenceMode=="mongo" (the default) requires a reachable Mongo with
// successful index creation in EnvProduction: a connect/ping/index failure
// is fatal there, since silently continuing on in-memory repositories would
// lose project guards, idempotency records, KYC events, transaction
// tracking, audit logs, and indexer checkpoints on the next restart while
// still reporting ready. Outside
// production it still falls back with a loud warning, preserving the old
// no-docker-compose developer convenience.
func connectRepositories(ctx context.Context, cfg config.Config) (*repository.Repositories, *mongodriver.Client) {
	if cfg.PersistenceMode == "memory" {
		log.Printf("platform: PERSISTENCE_MODE=memory — using in-memory repositories (not durable; refused in production)")
		return memory.New(), nil
	}

	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	client, err := dal.Connect(connectCtx, cfg.MongoURI)
	if err != nil {
		return fallbackOrFatal(cfg, "MongoDB connect failed", err)
	}
	if err := client.Ping(connectCtx, nil); err != nil {
		return fallbackOrFatal(cfg, "MongoDB ping failed", err)
	}
	db := client.Database(cfg.MongoDB)
	if err := mongodb.EnsureIndexes(connectCtx, db); err != nil {
		if cfg.Environment == config.EnvProduction {
			log.Fatalf("platform: EnsureIndexes failed: %v (fatal in production with mongo persistence)", err)
		}
		log.Printf("platform: EnsureIndexes failed: %v", err)
	}
	log.Printf("platform: connected to MongoDB at %s (db=%s)", cfg.MongoURI, cfg.MongoDB)
	return mongodb.New(db), client
}

// fallbackOrFatal is connectRepositories' shared handling for a Mongo
// connect/ping failure: fatal in production, a logged in-memory fallback
// everywhere else (see connectRepositories' doc comment).
func fallbackOrFatal(cfg config.Config, reason string, err error) (*repository.Repositories, *mongodriver.Client) {
	if cfg.Environment == config.EnvProduction {
		log.Fatalf("platform: %s (%v); refusing to start on volatile in-memory repositories in production", reason, err)
	}
	log.Printf("platform: %s (%v); falling back to in-memory repositories (not allowed in production)", reason, err)
	return memory.New(), nil
}

// loadComplianceKey materializes Config.ComplianceKey into an
// ed25519.PrivateKey. It accepts either form the operator might reasonably
// provision: a base58-encoded 64-byte secret key (seed+pubkey — the same
// form crypto/ed25519.PrivateKey and the RAW BYTES of a Solana CLI keypair
// file use), tried first, or — if that doesn't decode to exactly 64 bytes —
// a filesystem path to a Solana CLI-style keypair JSON file (`solana-keygen
// new`'s output: a JSON array of 64 integers).
//
// This does NOT go through internal/keys' Provider abstraction — this is a
// deliberate, flagged V1 simplification: only "raw" materials (inline
// base58 or a plaintext keypair file) are supported for now; a future pass
// can extend internal/keys instead of this codebase inventing a second,
// parallel key-custody abstraction prematurely.
// loadComplianceKey's error paths never include `raw` itself, nor a
// %w-wrapped *fs.PathError from os.ReadFile (which embeds its path
// argument — here, `raw` again) — see below. A near-miss malformed inline
// secret (e.g. a mistyped base58 key one operator meant to paste as the
// inline form) must never be echoed verbatim into a log line by a caller
// like buildApp's log.Printf: only the two attempted
// forms and non-sensitive shape information (byte counts) are reported.
func loadComplianceKey(raw string) (ed25519.PrivateKey, error) {
	if b, err := base58.Decode(raw); err == nil && len(b) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(b), nil
	}
	data, err := os.ReadFile(raw)
	if err != nil {
		// Deliberately does NOT wrap err: os.ReadFile's *fs.PathError embeds
		// its path argument, which here is `raw` itself — exactly the value
		// this comment says must never be echoed. len(raw) is reported
		// instead of the value, along with the OS-level failure "kind" (not
		// the raw error text, which could itself contain the path on some
		// platforms/wrappers) so a genuine "file not found" is still
		// distinguishable from other failures without leaking the value.
		return nil, fmt.Errorf("security.compliance_key is neither a base58 %d-byte ed25519 secret key nor a readable keypair file (%d bytes of config value elided; open failed: %v)", ed25519.PrivateKeySize, len(raw), errors.Unwrap(err))
	}
	var ints []int
	if err := json.Unmarshal(data, &ints); err != nil {
		return nil, fmt.Errorf("security.compliance_key names a file that is not valid keypair JSON (a JSON array of %d integers): %w", ed25519.PrivateKeySize, err)
	}
	if len(ints) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("security.compliance_key keypair file has %d bytes, want %d", len(ints), ed25519.PrivateKeySize)
	}
	key := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	for i, v := range ints {
		if v < 0 || v > 255 {
			return nil, fmt.Errorf("security.compliance_key keypair file has an out-of-range byte value at index %d", i)
		}
		key[i] = byte(v)
	}
	return key, nil
}

// newIPFSReplicationManager builds an ipfs.ReplicationManager over local
// plus every configured backup destination, or nil if no
// backup is configured — a bare local Kubo client alone provides no
// independent backup pinning destination, so callers fall back
// to using local directly rather than wrapping it in a ReplicationManager
// that could never reach PublicationReplicated. Called both when building
// the request-serving App (buildApp) and, separately, by
// startBackgroundLoops for the periodic retrieval-verification ticker — a
// fresh, stateless value each time.
func newIPFSReplicationManager(cfg config.Config, local ipfs.Client, repos *repository.Repositories) *ipfs.ReplicationManager {
	var backups []ipfs.Destination
	if cfg.IPFSBackupArchiveDir != "" {
		archive, err := ipfs.NewFileArchiveClient(cfg.IPFSBackupArchiveDir)
		if err != nil {
			log.Fatalf("platform: IPFS_BACKUP_ARCHIVE_DIR: %v", err)
		}
		backups = append(backups, ipfs.Destination{Name: "archive", Client: archive})
	}
	if cfg.IPFSBackupKuboURL != "" {
		backups = append(backups, ipfs.Destination{Name: "backup-kubo", Client: ipfs.NewKuboClient(cfg.IPFSBackupKuboURL)})
	}
	if len(backups) == 0 {
		return nil
	}
	return ipfs.NewReplicationManager(local, backups, cfg.IPFSReplicationThreshold, repos.Publications)
}

// checkStorageHealth pings Mongo and reports degradation: a log line, an
// audit-log entry, and a Prometheus counter increment, plus the
// rwa_storage_up gauge for dashboards/alertmanager so repository
// degradation is alertable. Not currently wired into
// startBackgroundLoops (kept available as chain-neutral machinery);
// GET /health's ReadyCheck already pings Mongo on every probe.
func checkStorageHealth(ctx context.Context, mongoClient *mongodriver.Client, app *api.App) {
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := mongoClient.Ping(pingCtx, nil); err != nil {
		metrics.StorageUp.Set(0)
		log.Printf("platform: ALERT [storage_degraded] MongoDB ping failed: %v", err)
		metrics.AlertsFiredTotal.WithLabelValues("storage_degraded").Inc()
		if app.Audit != nil {
			_ = app.Audit.Record(ctx, "alerts", "system", "alerts.storage_degraded", "mongo", map[string]any{"error": err.Error()})
		}
		return
	}
	metrics.StorageUp.Set(1)
}

// refreshBusinessGauges recomputes the Prometheus business gauges
// (internal/metrics) from live repo/chain state. Best-effort: a failed
// read leaves the previous gauge value in place rather than zeroing it out
// (a stale-but-plausible dashboard value is more useful than a misleading
// "0 inventory" blip caused by one failed RPC call). Not currently wired
// into startBackgroundLoops (app.Sales.GetInventory always returns
// sales.ErrNoChainClient for the read-only sales service — see
// buildApp — so the inventory half is a no-op today); kept available
// as chain-neutral machinery, and the redemption-gauge half needs no chain
// client at all.
func refreshBusinessGauges(ctx context.Context, repos *repository.Repositories, app *api.App) {
	if app.Sales != nil {
		if inv, err := app.Sales.GetInventory(ctx); err == nil {
			if tokens, ok := new(big.Float).SetString(inv.Inventory); ok {
				whole, _ := new(big.Float).Quo(tokens, big.NewFloat(1e18)).Float64()
				metrics.SalesInventoryTokens.Set(whole)
			}
		}
	}

	requests, err := repos.RedemptionRequests.List(ctx, "")
	if err != nil {
		log.Printf("platform: business-gauge refresh: listing redemption requests: %v", err)
		return
	}
	now := time.Now().UTC()
	pendingCount, fundedUnclaimed := 0, 0
	oldestPendingAge := time.Duration(0)
	for _, r := range requests {
		switch r.Status {
		case models.RedemptionPending:
			pendingCount++
			if age := now.Sub(time.Unix(r.CreatedAt, 0).UTC()); age > oldestPendingAge {
				oldestPendingAge = age
			}
		case models.RedemptionFunded:
			fundedUnclaimed++
		}
	}
	metrics.RedemptionsPendingCount.Set(float64(pendingCount))
	metrics.RedemptionsPendingOldestAgeSeconds.Set(oldestPendingAge.Seconds())
	metrics.RedemptionsFundedUnclaimedCount.Set(float64(fundedUnclaimed))
}

// evaluateAlerts runs the alert evaluators (internal/alerts) against the
// current redemption read model and reports every finding: a log line, an
// audit-log entry (so it shows up on GET /api/v1/audit-logs alongside every
// other operational event), and a Prometheus counter increment. Not
// currently wired into startBackgroundLoops; kept available as
// chain-neutral machinery (its inputs — redemption requests — are already
// populated by redemption.Reconcile).
func evaluateAlerts(ctx context.Context, cfg config.Config, repos *repository.Repositories, app *api.App) {
	requests, err := repos.RedemptionRequests.List(ctx, "")
	if err != nil {
		log.Printf("platform: alert evaluation: listing redemption requests: %v", err)
		return
	}
	now := time.Now().UTC()
	findings := alerts.EvaluatePendingRedemptionSLA(requests, cfg.PendingRedemptionSLA, now)
	findings = append(findings, alerts.EvaluateFundedClaimFailure(requests, cfg.FundedClaimFailureSLA, now)...)

	for _, a := range findings {
		log.Printf("platform: ALERT [%s] %s", a.Kind, a.Message)
		metrics.AlertsFiredTotal.WithLabelValues(a.Kind).Inc()
		if app.Audit != nil {
			_ = app.Audit.Record(ctx, "alerts", "system", "alerts."+a.Kind, a.RedemptionID, map[string]any{
				"message": a.Message, "since": a.Since, "ageSeconds": a.Age.Seconds(),
			})
		}
	}
}

// redemptionTimeoutSeconds reads the immutable per-deployment redemption
// timeout from the project record, falling back to the recommended 14-day
// default if the project hasn't finished deploying yet. Not currently
// called by startBackgroundLoops (redemption.Reconcile instead
// reads cfg.RedemptionTimeout directly — the project record
// has no on-chain deploy-request capture to read a per-deployment value
// from); kept as chain-neutral machinery.
func redemptionTimeoutSeconds(ctx context.Context, repos *repository.Repositories) int64 {
	const defaultTimeout = 14 * 24 * 60 * 60
	p, err := repos.Projects.Get(ctx)
	if err != nil || p.RedemptionTimeout == 0 {
		return defaultTimeout
	}
	return p.RedemptionTimeout
}

func runTicker(ctx context.Context, interval time.Duration, fn func()) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fn()
		}
	}
}

// indexerUnsafe reports whether chainID's indexer checkpoint (keyed by the
// chain-neutral blockchain.CheckpointAddress sentinel) is currently
// ReconciliationRequired. No checkpoint yet is NOT unsafe — that's the
// normal state before any writer has ever set the flag, not a divergence.
// The indexer never writes this checkpoint at all (it has no reorg
// handling — see startBackgroundLoops' doc comment), so this always
// reports "safe" for this deployment today; it exists so
// runIndexDependentTicker/runAsReconcilerLeader remain available machinery
// for a future reconciler that does need this gate.
func indexerUnsafe(ctx context.Context, repos *repository.Repositories, chainID int64) (bool, error) {
	cp, err := repos.IndexerCheckpoints.Get(ctx, chainID, blockchain.CheckpointAddress)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return cp.ReconciliationRequired, nil
}

// runIndexDependentTicker is runTicker plus an indexer-safety gate: fn is
// skipped entirely (not called) for any tick where indexerUnsafe reports
// true. Not currently called by startBackgroundLoops (see its doc
// comment: the indexer has no ReconciliationRequired state to guard
// against), but kept as chain-neutral machinery.
// runIndexDependentTicker's fn returns its error instead of logging it
// itself so this wrapper can both log AND record it on
// metrics.ReadModelReconcileErrorsTotal in one place.
func runIndexDependentTicker(ctx context.Context, repos *repository.Repositories, cfg config.Config, interval time.Duration, name string, fn func() error) {
	runTicker(ctx, interval, func() {
		switch unsafe, err := indexerUnsafe(ctx, repos, cfg.ChainID); {
		case err != nil:
			log.Printf("platform: %s: check indexer safety: %v", name, err)
		case unsafe:
			log.Printf("platform: %s: skipped — indexer reconciliation required", name)
		default:
			runAsReconcilerLeader(ctx, repos, cfg, name, func() {
				if err := fn(); err != nil {
					log.Printf("platform: %s: %v", name, err)
					metrics.ReadModelReconcileErrorsTotal.WithLabelValues(name).Inc()
				}
			})
		}
	})
}

// reconcilerHolderID is this process's identity for the per-reconciler
// leader lease below — it serializes one reconciler leader per
// project/chain in multi-instance mode, generated once per process start.
var reconcilerHolderID = uuid.NewString()

// reconcilerLeaseTTL bounds how long a crashed leader's lease blocks
// another replica from taking over — generous relative to every
// reconciler's tick interval so a merely-slow (not crashed) pass is
// never preempted mid-run by a second replica.
const reconcilerLeaseTTL = 60 * time.Second

// runAsReconcilerLeader acquires a short lease keyed by (name, chainID)
// before running fn, using repos.Leases as the distributed fencing
// primitive. At most one replica's tick actually executes a given
// reconciler at a time; a replica whose Acquire fails (another replica
// currently holds the lease) simply skips this tick instead of racing a
// concurrent Upsert/DeleteStaleGeneration pass against the same
// collection — without the lease, multiple replicas amplify the race
// because their delete/reinsert phases can interleave. A single-replica
// deployment, or PERSISTENCE_MODE=memory dev, always acquires immediately
// since nothing else ever holds the key.
func runAsReconcilerLeader(ctx context.Context, repos *repository.Repositories, cfg config.Config, name string, fn func()) {
	key := fmt.Sprintf("reconciler:%s:%d", name, cfg.ChainID)
	token, ok, err := repos.Leases.Acquire(ctx, key, reconcilerHolderID, reconcilerLeaseTTL)
	if err != nil {
		log.Printf("platform: %s: acquire reconciler leader lease: %v", name, err)
		return
	}
	if !ok {
		// Another replica is currently the leader for this reconciler —
		// not an error, just this tick's no-op.
		return
	}
	defer func() {
		relCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := repos.Leases.Release(relCtx, key, reconcilerHolderID, token); err != nil {
			log.Printf("platform: %s: release reconciler leader lease: %v", name, err)
		}
	}()
	fn()
}
