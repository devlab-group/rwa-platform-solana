// Package policy loads the auditor's independently-provisioned deployment
// trust root: a small local JSON file, maintained by the auditor themselves
// and never taken from the .rwa package under review, that pins the Solana
// cluster, program, config PDA, Vault, auditor address, project, and profile
// digest; the signer refuses to sign anything that doesn't match.
//
// The alternative we rejected was a set of optional --expect-* flags:
// omitting all of them would let the signer sign using only values the
// package itself supplied, collapsing the independent air-gapped
// verification boundary into a self-consistency check the package producer
// fully controls. A policy file is mandatory for every sign invocation.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/rwa-platform/signer/internal/base58"
)

// Shared shape checks for policy fields that are hex-encoded rather than
// base58.
var (
	addressPattern = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	digestPattern  = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)
)

// DefaultMaxAttestationLifetime is the maximum allowed gap between
// metadata.createdAt and typed-data validUntil when a policy file does not
// override it via maxAttestationLifetimeHours. Roughly 30 days.
const DefaultMaxAttestationLifetime = 30 * 24 * time.Hour

// Policy is the auditor's trust root for a deployment: cluster, program,
// and config PDA bind the domain, and Vault is carried as a Solana pubkey
// rather than a 20-byte address.
type Policy struct {
	// Cluster, Program, Config, Vault are kept in their base58 form, which
	// is what the auditor provisioned and what the review screen shows.
	// Decoded32 below is the byte form the digest actually uses; both are
	// derived from the same string so they cannot disagree.
	Cluster string
	Program string
	Config  string
	Vault   string

	ClusterBytes [32]byte
	ProgramBytes [32]byte
	ConfigBytes  [32]byte
	VaultBytes   [32]byte

	// Auditor is the 20-byte eth address the signature must recover to.
	// Solana verifies secp256k1 signatures by eth-address derivation, so
	// the auditor identity stays a 20-byte address even though everything
	// else in this policy is Solana-shaped.
	Auditor       string
	ProjectID     string
	ProfileDigest string

	MaxAttestationLifetime time.Duration
}

type fileShape struct {
	Cluster                     string  `json:"cluster"`
	Program                     string  `json:"program"`
	Config                      string  `json:"config"`
	Vault                       string  `json:"vault"`
	Auditor                     string  `json:"auditor"`
	ProjectID                   string  `json:"projectId"`
	ProfileDigest               string  `json:"profileDigest"`
	MaxAttestationLifetimeHours float64 `json:"maxAttestationLifetimeHours,omitempty"`
}

// Load reads and validates a policy file from path. Every field except
// maxAttestationLifetimeHours is required; a missing, malformed or
// incomplete policy file is a hard failure.
func Load(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: reading %s: %w", path, err)
	}

	var f fileShape
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("policy: parsing %s: %w", path, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("policy: %s: trailing data after JSON value", path)
	}

	required := []struct{ name, value string }{
		{"cluster", f.Cluster},
		{"program", f.Program},
		{"config", f.Config},
		{"vault", f.Vault},
		{"auditor", f.Auditor},
		{"projectId", f.ProjectID},
		{"profileDigest", f.ProfileDigest},
	}
	for _, r := range required {
		if strings.TrimSpace(r.value) == "" {
			return nil, fmt.Errorf("policy: %s: field %q is required and must be non-empty", path, r.name)
		}
	}

	p := &Policy{
		Cluster:       f.Cluster,
		Program:       f.Program,
		Config:        f.Config,
		Vault:         f.Vault,
		Auditor:       f.Auditor,
		ProjectID:     f.ProjectID,
		ProfileDigest: f.ProfileDigest,
	}
	for _, k := range []struct {
		name  string
		value string
		out   *[32]byte
	}{
		{"cluster", f.Cluster, &p.ClusterBytes},
		{"program", f.Program, &p.ProgramBytes},
		{"config", f.Config, &p.ConfigBytes},
		{"vault", f.Vault, &p.VaultBytes},
	} {
		b, err := base58.DecodePubkey(k.value)
		if err != nil {
			return nil, fmt.Errorf("policy: %s: field %q must be a base58 32-byte Solana public key: %w", path, k.name, err)
		}
		*k.out = b
	}

	if !addressPattern.MatchString(f.Auditor) {
		return nil, fmt.Errorf("policy: %s: auditor must be a 0x-prefixed 20-byte address, got %q", path, f.Auditor)
	}
	if !digestPattern.MatchString(f.ProfileDigest) {
		return nil, fmt.Errorf("policy: %s: profileDigest must be a 0x-prefixed 32-byte hex value, got %q", path, f.ProfileDigest)
	}
	if f.MaxAttestationLifetimeHours < 0 {
		return nil, fmt.Errorf("policy: %s: maxAttestationLifetimeHours must not be negative", path)
	}

	p.MaxAttestationLifetime = DefaultMaxAttestationLifetime
	if f.MaxAttestationLifetimeHours > 0 {
		p.MaxAttestationLifetime = time.Duration(f.MaxAttestationLifetimeHours * float64(time.Hour))
	}
	return p, nil
}
