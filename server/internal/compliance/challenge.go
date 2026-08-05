// Package compliance implements wallet-ownership challenges, the KYC
// webhook, and compliance status transaction submission. It never itself
// decides KYC outcomes — it only (a) proves a wallet
// is controlled by whoever claims it before that wallet can be trusted in a
// webhook update, and (b) relays an already-decided status onto
// ComplianceRegistry via a hot key.
package compliance

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/rwa-platform/server/internal/auth"
	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
)

// ErrChallengeUsed is returned by VerifyChallenge for a replayed challenge.
var ErrChallengeUsed = errors.New("compliance: challenge already used")

// ErrChallengeExpired is returned by VerifyChallenge for an expired challenge.
var ErrChallengeExpired = errors.New("compliance: challenge expired")

// ErrAddressMismatch is returned when the recovered signer does not match
// the address the challenge was issued for.
var ErrAddressMismatch = errors.New("compliance: recovered signer does not match challenge address")

// ErrTooManyActiveChallenges is returned by Create when address has already
// accumulated MaxActiveChallengesPerAddress currently-unexpired, unused
// challenges: the number of ACTIVE challenges per normalized address is
// capped. The caller should wait for an
// existing challenge to be used or to expire rather than retry immediately.
var ErrTooManyActiveChallenges = errors.New("compliance: too many active challenges for this address")

// DefaultMaxActiveChallengesPerAddress is the out-of-the-box value of
// ChallengeService.MaxActiveChallengesPerAddress:
// an unauthenticated caller can request a fresh challenge (new nonce, new
// stored document) for any valid address at will; capping how many of
// THOSE documents may be simultaneously active per address bounds storage
// growth independent of — and available immediately, unlike — the Mongo
// wallet_challenges TTL index (internal/dal/mongodb/mongodb.go),
// which only reclaims storage after the fact.
const DefaultMaxActiveChallengesPerAddress = 20

// ChallengeService issues and verifies one-time wallet-ownership challenges,
// including nonce-based replay protection.
//
// The signature primitive and address shape are delegated to a
// auth.Verifier (see cmd/platform's wiring): Solana ed25519 wallet-standard
// signMessage + base58 pubkey — see auth.Verifier's doc comment.
type ChallengeService struct {
	repo      repository.WalletChallengeRepository
	investors repository.InvestorRepository
	ttl       time.Duration
	domain    string
	verifier  auth.Verifier
	// MaxActiveChallengesPerAddress caps Create: a
	// request for address that already has this many currently-unexpired,
	// unused challenges outstanding is rejected with
	// ErrTooManyActiveChallenges instead of minting yet another one. <= 0
	// disables the cap entirely (unbounded). Exported so
	// a deployment can retune it without a NewChallengeService signature
	// change; NewChallengeService sets it to
	// DefaultMaxActiveChallengesPerAddress.
	MaxActiveChallengesPerAddress int
}

// NewChallengeService constructs a ChallengeService. domainName appears in
// the human-readable challenge message (e.g. the issuer's site name).
// investors is used only by VerifyOwnership to record the ownership-proven
// flag; pass nil if the caller never calls VerifyOwnership (Create/Verify
// alone don't need it). verifier selects the chain-specific signature
// primitive (see auth.Verifier/auth.NewVerifier).
func NewChallengeService(repo repository.WalletChallengeRepository, investors repository.InvestorRepository, ttl time.Duration, domainName string, verifier auth.Verifier) *ChallengeService {
	return &ChallengeService{
		repo: repo, investors: investors, ttl: ttl, domain: domainName, verifier: verifier,
		MaxActiveChallengesPerAddress: DefaultMaxActiveChallengesPerAddress,
	}
}

// Create issues a new challenge for address. The challenge's repository key
// is its nonce (api Schemas.ChallengeVerify identifies a challenge by
// {address, nonce}, not a separate opaque id), so a client only ever needs
// to remember the Challenge response's `nonce` field to complete verification.
func (s *ChallengeService) Create(ctx context.Context, address string) (*models.WalletChallenge, error) {
	if !s.verifier.ValidateAddress(address) {
		return nil, fmt.Errorf("compliance: invalid address %q", address)
	}
	normalized := s.verifier.NormalizeAddress(address)
	if s.MaxActiveChallengesPerAddress > 0 {
		now := time.Now().UTC()
		active, err := s.repo.CountActive(ctx, normalized, now)
		if err != nil {
			return nil, fmt.Errorf("compliance: count active challenges: %w", err)
		}
		if active >= s.MaxActiveChallengesPerAddress {
			return nil, ErrTooManyActiveChallenges
		}
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("compliance: generate nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)
	now := time.Now().UTC()
	expiresAt := now.Add(s.ttl)

	message := fmt.Sprintf(
		"%s wants you to prove ownership of this wallet.\nAddress: %s\nNonce: %s\nIssued At: %s\nExpires At: %s",
		s.domain, normalized, nonce, now.Format(time.RFC3339), expiresAt.Format(time.RFC3339),
	)

	c := &models.WalletChallenge{
		ID: nonce, Address: normalized, Nonce: nonce, Message: message,
		ExpiresAt: expiresAt, Used: false, CreatedAt: now,
	}
	if err := s.repo.Create(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

// Verify checks a wallet signature over the challenge identified by nonce,
// enforcing single-use and expiry, and returns the canonical signer address.
// It does not touch the investors repository; use VerifyOwnership for the
// full HTTP-facing flow that also records the ownership-proven flag.
func (s *ChallengeService) Verify(ctx context.Context, nonce string, signature []byte) (string, error) {
	c, err := s.repo.Get(ctx, nonce)
	if err != nil {
		return "", err
	}
	if c.Used {
		return "", ErrChallengeUsed
	}
	if time.Now().UTC().After(c.ExpiresAt) {
		return "", ErrChallengeExpired
	}

	recovered, err := s.verifier.Verify(c.Message, c.Address, signature)
	if err != nil {
		return "", fmt.Errorf("compliance: signature verification: %w", err)
	}
	if recovered != c.Address {
		return "", ErrAddressMismatch
	}

	// Mark used before returning success so a concurrent replay of the same
	// signature cannot also succeed: MarkUsed is a genuine compare-and-swap
	// (see WalletChallengeRepository's doc comment), so if another request
	// for this same nonce already won that race, ErrAlreadyExists comes
	// back here and this call correctly loses instead of both succeeding.
	if err := s.repo.MarkUsed(ctx, c.ID); err != nil {
		if errors.Is(err, repository.ErrAlreadyExists) {
			return "", ErrChallengeUsed
		}
		return "", err
	}
	return recovered, nil
}

// VerifyOwnership implements POST /api/v1/compliance/challenge/verify: it
// verifies the signature (via Verify), confirms the caller-claimed address
// matches the actual recovered signer, and upserts the investor's
// OwnershipVerified flag — the precondition the KYC webhook checks before
// accepting a status change for that wallet.
func (s *ChallengeService) VerifyOwnership(ctx context.Context, address, nonce string, signature []byte) (*models.Investor, error) {
	recovered, err := s.Verify(ctx, nonce, signature)
	if err != nil {
		return nil, err
	}
	if s.verifier.NormalizeAddress(address) != recovered {
		return nil, ErrAddressMismatch
	}

	now := time.Now().UTC()
	inv, err := s.investors.Get(ctx, recovered)
	if err != nil {
		if !errors.Is(err, repository.ErrNotFound) {
			return nil, err
		}
		inv = &models.Investor{Address: recovered, Status: models.ComplianceUnknown, CreatedAt: now}
	}
	inv.OwnershipVerified = true
	inv.UpdatedAt = now
	if err := s.investors.Upsert(ctx, inv); err != nil {
		return nil, err
	}
	return inv, nil
}
