package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/rwa-platform/signer/internal/attestation"
	"github.com/rwa-platform/signer/internal/base58"
	"github.com/rwa-platform/signer/internal/output"
	"github.com/rwa-platform/signer/internal/policy"
	"github.com/rwa-platform/signer/internal/ui"
)

// wellKnownClusters maps a cluster genesis hash to its public name, purely so
// the review screen can say "mainnet-beta" instead of only showing 44 base58
// characters. It is a display hint and nothing more: the cluster the signature
// actually binds is the base58 value, and that value is enforced against
// --policy. An unrecognized hash is therefore not an error -- a private
// validator or a fresh local cluster is perfectly legitimate -- it just gets no
// friendly name.
var wellKnownClusters = map[string]string{
	"5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d": "mainnet-beta",
	"EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG": "devnet",
	"4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY": "testnet",
}

func clusterLabel(genesisHash string) string {
	if name, ok := wellKnownClusters[genesisHash]; ok {
		return fmt.Sprintf("%s (matches the well-known %s genesis hash)", genesisHash, name)
	}
	return fmt.Sprintf("%s (not a well-known public cluster -- verify against your own records)", genesisHash)
}

// pubkeyField renders a Solana public key as base58 plus hex. The base58 form
// is the one an auditor can compare against their records or an explorer; the
// hex is what actually enters the digest. Showing both means a mismatch
// between the two representations cannot hide.
func pubkeyField(b58 string, raw [32]byte) string {
	return fmt.Sprintf("%s  (hex 0x%x)", b58, raw)
}

func runSign(args []string) error {
	// The package path is a fixed leading positional argument, not parsed
	// by the flag package: Go's flag.Parse stops consuming flags at the
	// first non-flag token, so "signer sign <package.rwa> --keystore X"
	// (package path before flags, per usage()) would otherwise leave
	// --keystore unparsed.
	if len(args) == 0 {
		usage()
		return fmt.Errorf("expected a <package.rwa> argument")
	}
	pkgPath := args[0]

	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	var f signFlags
	fs.StringVar(&f.keystorePath, "keystore", "", "password-encrypted Ethereum keystore file")
	fs.StringVar(&f.password, "password", "", "DEPRECATED, INSECURE: keystore password on the command line")
	fs.StringVar(&f.passwordFile, "password-file", "", "file containing the keystore password")
	fs.StringVar(&f.hardware, "hardware", "", "sign with a hardware-wallet adapter (ledger, trezor, yubikey, hsm)")
	fs.StringVar(&f.out, "out", "", "output path for signed-result-solana.json")
	fs.StringVar(&f.policyPath, "policy", "", "REQUIRED: path to the independently-provisioned Solana deployment policy file")
	fs.StringVar(&f.typedDataPath, "typed-data", "", "path to the Solana attestation request JSON; defaults to the package's own typed-data.json entry when omitted, and must match it byte-for-byte when both are given")
	fs.BoolVar(&f.yes, "yes", false, "skip interactive confirmation (requires --unsafe-test-mode)")
	fs.BoolVar(&f.unsafeTestMode, "unsafe-test-mode", false, "required alongside --yes for noninteractive signing")
	fs.StringVar(&f.auditAnchor, "audit-anchor", "", "path to the keystore's independent audit-log anchor")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		usage()
		return fmt.Errorf("unexpected extra arguments: %v", fs.Args())
	}

	if f.hardware == "" && f.keystorePath == "" {
		return fmt.Errorf("--keystore is required (or pass --hardware <device>)")
	}
	if f.policyPath == "" {
		return fmt.Errorf("--policy is required: the signer refuses to sign without an independently-provisioned deployment trust root; see internal/policy and docs/auditor/auditor-guide.md")
	}
	// --typed-data itself is no longer mandatory: it defaults to the
	// package's own typed-data.json entry (see resolveTypedData). What
	// is mandatory is that *some* attestation request end up bound to the
	// package, which resolveTypedData enforces once the package has
	// been extracted below.
	if f.yes && !f.unsafeTestMode {
		return fmt.Errorf("--yes requires --unsafe-test-mode: noninteractive signing bypasses the human confirmation step and is restricted to scripted test/CI use")
	}

	pol, err := policy.Load(f.policyPath)
	if err != nil {
		return fmt.Errorf("loading --policy: %w", err)
	}

	vp, err := validatePackage(pkgPath, pol.ProjectID, pol.ProfileDigest)
	if err != nil {
		return err
	}
	prof, meta := vp.profile, vp.metadata

	typedDataRaw, typedDataSource, err := resolveTypedData(vp, f.typedDataPath)
	if err != nil {
		return err
	}
	td, err := parseAttestationRequest(typedDataRaw)
	if err != nil {
		return err
	}
	if td.PrimaryType != vp.manifest.PrimaryType {
		return fmt.Errorf("solana typed-data primaryType %q does not match manifest.json primaryType %q -- refusing to sign a %s using a package assembled for a %s", td.PrimaryType, vp.manifest.PrimaryType, td.PrimaryType, vp.manifest.PrimaryType)
	}

	// Bind the request to the documents actually in the package: both
	// digests are recomputed, never taken from the request.
	if !strings.EqualFold(td.Message.ProfileDigest, vp.profileDigestHex) {
		return fmt.Errorf("solana typed-data message.profileDigest %s does not match recomputed profileDigest %s", td.Message.ProfileDigest, vp.profileDigestHex)
	}
	if !strings.EqualFold(td.Message.MetadataDigest, vp.metadataDigestHex) {
		return fmt.Errorf("solana typed-data message.metadataDigest %s does not match recomputed metadataDigest %s", td.Message.MetadataDigest, vp.metadataDigestHex)
	}

	amountFromMetadata, ok := new(big.Int).SetString(meta.IssuanceAmount, 10)
	if !ok {
		return fmt.Errorf("internal error: metadata issuance.amount %q failed to re-parse", meta.IssuanceAmount)
	}
	amountFromTypedData, ok := new(big.Int).SetString(td.Message.Amount, 10)
	if !ok {
		return fmt.Errorf("internal error: solana typed-data amount %q failed to re-parse", td.Message.Amount)
	}
	if amountFromMetadata.Cmp(amountFromTypedData) != 0 {
		return fmt.Errorf("metadata issuance.amount %s does not equal solana typed-data amount %s", meta.IssuanceAmount, td.Message.Amount)
	}

	if td.PrimaryType == "MintAttestation" {
		if td.Message.RecordID != meta.RecordID {
			return fmt.Errorf("solana typed-data message.recordId %q does not match metadata.json recordId %q", td.Message.RecordID, meta.RecordID)
		}
		// recordKey seeds the on-chain replay marker and is opaque to the
		// program, so the convention is ours to fix: keccak256(recordId).
		// Deriving it here rather than trusting the request is what makes
		// "one record, one mint" checkable by the auditor instead of
		// assertable by the package producer.
		recordKey := attestation.RecordKey(meta.RecordID)
		if "0x"+common.Bytes2Hex(recordKey[:]) != strings.ToLower(td.Message.RecordKey) {
			return fmt.Errorf("recomputed recordKey does not match solana typed-data message.recordKey")
		}
	}

	// Every domain component and the Vault come from the auditor's own
	// policy file, never from the request.
	for _, c := range []struct {
		name         string
		got, want    [32]byte
		gotS, want58 string
	}{
		{"domain.cluster", td.cluster, pol.ClusterBytes, td.Domain.Cluster, pol.Cluster},
		{"domain.program", td.program, pol.ProgramBytes, td.Domain.Program, pol.Program},
		{"domain.config", td.config, pol.ConfigBytes, td.Domain.Config, pol.Config},
		{"message.vault", td.vault, pol.VaultBytes, td.Message.Vault, pol.Vault},
	} {
		if c.got != c.want {
			return fmt.Errorf("solana typed-data %s %s does not match policy %s", c.name, c.gotS, c.want58)
		}
	}
	if !strings.EqualFold(pol.Auditor, td.Message.Auditor) {
		return fmt.Errorf("solana typed-data auditor %s does not match policy auditor %s", td.Message.Auditor, pol.Auditor)
	}

	// Expiry: a two-sided bound. metadata.createdAt is package-supplied and
	// therefore untrusted, so the ceiling is the earlier of now+lifetime and
	// createdAt+lifetime. The program itself enforces no maximum validity
	// window, so this two-sided bound is the only limit on how long a signed
	// attestation stays valid.
	createdAt, err := time.Parse(time.RFC3339, meta.CreatedAt)
	if err != nil {
		return fmt.Errorf("internal error: metadata.json createdAt %q failed to re-parse: %w", meta.CreatedAt, err)
	}
	now := time.Now().UTC()
	validUntil := time.Unix(int64(td.Message.ValidUntil), 0).UTC()
	if !validUntil.After(now) {
		return fmt.Errorf("solana typed-data validUntil %s is not after the current time %s -- refusing to sign a zero, already-expired, or non-future validUntil", validUntil.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	maxValidUntil := now.Add(pol.MaxAttestationLifetime)
	if fromCreated := createdAt.Add(pol.MaxAttestationLifetime); fromCreated.Before(maxValidUntil) {
		maxValidUntil = fromCreated
	}
	if validUntil.After(maxValidUntil) {
		return fmt.Errorf("solana typed-data validUntil %s exceeds the maximum attestation lifetime of %s (max allowed: %s, the earlier of now+lifetime and metadata.createdAt+lifetime)", validUntil.Format(time.RFC3339), pol.MaxAttestationLifetime, maxValidUntil.Format(time.RFC3339))
	}

	domain := td.domain()
	var digest common.Hash
	switch td.PrimaryType {
	case "MintAttestation":
		digest = td.mintAttestation().Digest(domain)
	case "BurnAttestation":
		digest = td.burnAttestation().Digest(domain)
	default:
		// Unreachable in practice: parseAttestationRequest already restricts
		// PrimaryType to "MintAttestation"/"BurnAttestation" (typeddata.go).
		// This default is defense-in-depth for the signing core itself -- without
		// it, a future unrecognized PrimaryType would fall through with digest
		// left at its zero value and get signed rather than rejected.
		return fmt.Errorf("solana typed-data: unsupported primaryType %q -- refusing to sign a zero digest", td.PrimaryType)
	}

	critical := []ui.Field{
		{Label: "chain", Value: "Solana (secp256k1 attestation; 64-byte compact signature + recoveryId)"},
		{Label: "primaryType", Value: td.PrimaryType},
		{Label: "profile.json projectId", Value: prof.ProjectID},
		{Label: "metadata.json projectId", Value: meta.ProjectID},
		{Label: "tokenUnit (profile) / issuance.unit (metadata)", Value: prof.TokenUnit},
		{Label: "tokenDecimals", Value: fmt.Sprintf("%d", prof.TokenDecimals)},
		{Label: "cluster (genesis hash)", Value: clusterLabel(td.Domain.Cluster)},
		{Label: "program (rwa-supply-controller)", Value: pubkeyField(td.Domain.Program, td.program)},
		{Label: "config PDA (SupplyController)", Value: pubkeyField(td.Domain.Config, td.config)},
		{Label: "auditor", Value: td.Message.Auditor},
		{Label: "vault (Vault authority PDA)", Value: pubkeyField(td.Message.Vault, td.vault)},
		{Label: "profileDigest", Value: td.Message.ProfileDigest},
		{Label: "metadataDigest", Value: td.Message.MetadataDigest},
		{Label: "amount (raw, smallest unit, uint64)", Value: td.Message.Amount},
		{Label: "amount (normalized)", Value: normalizedAmount(amountFromTypedData, prof.TokenDecimals) + " " + prof.TokenUnit},
		{Label: "nonce (bytes32)", Value: td.Message.Nonce},
		{Label: "validUntil (unix seconds)", Value: fmt.Sprintf("%d (%s, checked against policy: now < validUntil <= %s)", td.Message.ValidUntil, validUntil.Format(time.RFC3339), maxValidUntil.Format(time.RFC3339))},
		{Label: "attestation digest", Value: digest.Hex()},
		{Label: "policy file", Value: f.policyPath},
		{Label: "attestation request file", Value: typedDataSource},
	}
	if td.PrimaryType == "MintAttestation" {
		critical = append(critical,
			ui.Field{Label: "recordId", Value: td.Message.RecordID},
			ui.Field{Label: "recordKey", Value: td.Message.RecordKey},
		)
	} else {
		critical = append(critical, ui.Field{Label: "operationId", Value: td.Message.OperationID})
	}

	critical = append(critical, proofFields(meta, vp.files)...)

	displayFields := buildDisplayFields(prof, meta.Asset)

	ui.RenderActionBanner(os.Stdout, td.PrimaryType)
	ui.Render(os.Stdout, fmt.Sprintf("Review Solana %s — %s", td.PrimaryType, pkgPath), critical, displayFields)

	if !f.yes {
		confirmed, err := ui.Confirm(os.Stdout, os.Stdin, "Sign this Solana attestation")
		if err != nil {
			return err
		}
		if !confirmed {
			return fmt.Errorf("aborted: not confirmed")
		}
	}

	// signDigest returns the standard 65-byte [R || S || V] form (the same
	// shape crypto.Sign always produces), which is converted to the Solana
	// compact form below.
	ethSig, auditorAddr, err := signDigest(digest, f)
	if err != nil {
		return err
	}

	sig, err := attestation.CompactSignatureFromEth(ethSig)
	if err != nil {
		return fmt.Errorf("converting signature to the Solana compact form: %w", err)
	}
	if !sig.IsLowS() {
		return fmt.Errorf("internal error: produced a high-S signature, which the on-chain verifier rejects")
	}

	declaredAuditor := common.HexToAddress(td.Message.Auditor)
	if auditorAddr != declaredAuditor {
		return fmt.Errorf("signing key address %s does not match the declared auditor %s; refusing to write a signature that would not recover to the declared auditor", auditorAddr.Hex(), declaredAuditor.Hex())
	}
	// Recover from the converted signature specifically, not from the one
	// signDigest returned: the low-S normalization rewrites S and the
	// recovery id, and a bug there would produce a signature that verifies
	// nowhere. This checks the exact bytes that get written out.
	recovered, err := attestation.RecoverCompact(digest, sig)
	if err != nil {
		return fmt.Errorf("verifying the produced signature: %w", err)
	}
	if recovered != declaredAuditor {
		return fmt.Errorf("the produced signature recovers to %s, not the declared auditor %s; refusing to write it", recovered.Hex(), declaredAuditor.Hex())
	}

	result, err := output.New(
		auditorAddr.Hex(),
		td.PrimaryType,
		base58.Encode(td.cluster[:]),
		base58.Encode(td.program[:]),
		base58.Encode(td.config[:]),
		digest.Hex(),
		sig.Hex(),
		sig.RecoveryID,
	)
	if err != nil {
		return fmt.Errorf("building signed-result-solana.json: %w", err)
	}

	outPath := f.out
	if outPath == "" {
		outPath = filepath.Join(filepath.Dir(pkgPath), "signed-result-solana.json")
	}
	if err := output.Write(outPath, result); err != nil {
		return fmt.Errorf("writing signed-result-solana.json: %w", err)
	}

	fmt.Fprintf(os.Stdout, "\nSigned (Solana). Wrote %s\n", outPath)
	return nil
}

// resolveTypedData decides which bytes are "the" Solana attestation
// request to sign, and returns a human-readable description of where they
// came from for the review screen.
//
// typed-data.json is now a mandatory .rwa entry on Solana too,
// byte-for-byte the same document --typed-data takes, and it is covered by
// the manifest's SHA-256 like every other package file (validatePackage,
// via manifest.VerifyFiles, already proved vp.files["typed-data.json"]
// matches manifest.json before this function ever runs). That makes the
// in-package copy the integrity-protected, authoritative one:
//
//   - --typed-data omitted: sign the package's own entry. This is the normal
//     case now that the request travels inside the package.
//   - --typed-data given, no package entry: reject. A Solana package without
//     typed-data.json is not a package "signer sign" accepts,
//     regardless of what's passed on the command line.
//   - both given: they must agree byte-for-byte. A --typed-data file that
//     merely looks the same as the package's copy is exactly what this
//     check exists to catch, including the case where the package's own
//     entry is shaped for some other request entirely and only the external
//     file was crafted to look right.
//
// Either way, the returned bytes are always the package's own entry, so a
// mismatch can never result in signing content the manifest hash doesn't
// cover.
func resolveTypedData(vp *validatedPackage, externalPath string) (raw []byte, source string, err error) {
	embedded, hasEmbedded := vp.files["typed-data.json"]

	if externalPath == "" {
		if !hasEmbedded {
			return nil, "", fmt.Errorf("package is missing typed-data.json, and --typed-data was not given -- a Solana .rwa package must carry its own attestation request")
		}
		return embedded, "typed-data.json (from the package)", nil
	}

	external, err := os.ReadFile(externalPath)
	if err != nil {
		return nil, "", fmt.Errorf("reading --typed-data: %w", err)
	}
	if !hasEmbedded {
		return nil, "", fmt.Errorf("package is missing typed-data.json -- a Solana .rwa package must carry its own attestation request, even when --typed-data is also given")
	}
	if !bytes.Equal(external, embedded) {
		return nil, "", fmt.Errorf("--typed-data %s does not match the package's own typed-data.json byte-for-byte -- the manifest-protected copy inside the package and the external file must be the same document", externalPath)
	}
	return embedded, externalPath + " (matches the package's own typed-data.json)", nil
}
