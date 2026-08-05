package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/rwa-platform/signer/internal/metadata"
	rwapkg "github.com/rwa-platform/signer/internal/package"
	"github.com/rwa-platform/signer/internal/profile"
)

// validatedPackage is a .rwa package that has passed every chain-independent
// check: safe extraction, manifest/file agreement, schema validation of both
// JSON documents, the cross-document binding between them, and agreement with
// the auditor's policy on projectId and profileDigest.
//
// Everything here is recomputed from the package's own bytes. Nothing in it is
// a value the package merely asserted about itself.
type validatedPackage struct {
	manifest *rwapkg.Manifest
	profile  *profile.Profile
	metadata *metadata.Metadata
	// files is every extracted entry except manifest.json.
	files map[string][]byte
	// profileDigestHex and metadataDigestHex are recomputed (SHA-256 over
	// JCS bytes), 0x-prefixed, never read from the package.
	profileDigestHex  string
	metadataDigestHex string
}

// validatePackage performs the chain-independent half of a signing run:
// safe extraction, manifest/file agreement, and schema validation of both
// JSON documents. The chain-specific typed data -- domain, nonce, vault,
// validUntil -- is checked by the caller.
func validatePackage(pkgPath, policyProjectID, policyProfileDigest string) (*validatedPackage, error) {
	zipBytes, err := rwapkg.ReadPackageFile(pkgPath, rwapkg.MaxCompressedSize)
	if err != nil {
		return nil, fmt.Errorf("reading package: %w", err)
	}

	files, err := rwapkg.Extract(zipBytes, rwapkg.DefaultOptions())
	if err != nil {
		return nil, fmt.Errorf("extracting package: %w", err)
	}

	manifestRaw, ok := files["manifest.json"]
	if !ok {
		return nil, fmt.Errorf("package is missing manifest.json")
	}
	manifest, err := rwapkg.ParseManifest(manifestRaw)
	if err != nil {
		return nil, fmt.Errorf("manifest.json: %w", err)
	}
	// manifest.json itself is not listed among its own "files".
	filesExceptManifest := make(map[string][]byte, len(files))
	for k, v := range files {
		if k != "manifest.json" {
			filesExceptManifest[k] = v
		}
	}
	if err := manifest.VerifyFiles(filesExceptManifest); err != nil {
		return nil, fmt.Errorf("verifying package files against manifest: %w", err)
	}

	profileRaw, ok := files["profile.json"]
	if !ok {
		return nil, fmt.Errorf("package is missing profile.json")
	}
	prof, err := profile.Validate(profileRaw)
	if err != nil {
		return nil, fmt.Errorf("profile.json: %w", err)
	}

	metadataRaw, ok := files["metadata.json"]
	if !ok {
		return nil, fmt.Errorf("package is missing metadata.json")
	}
	meta, err := metadata.Validate(metadataRaw)
	if err != nil {
		return nil, fmt.Errorf("metadata.json: %w", err)
	}

	if err := prof.ValidateAsset(meta.Asset); err != nil {
		return nil, fmt.Errorf("metadata.json: asset does not conform to the project's Asset Profile: %w", err)
	}

	// Cross-document binding: profile.json and metadata.json are otherwise
	// validated independently, so nothing above stops a package from pairing
	// an audited profile with metadata that actually describes a different
	// project or legal unit. The contract only checks hashes and the auditor
	// signature -- not JSON semantics -- so an unbound mismatch here could
	// authorize minting under the wrong project or unit.
	if meta.ProjectID != prof.ProjectID {
		return nil, fmt.Errorf("metadata.json projectId %q does not match profile.json projectId %q", meta.ProjectID, prof.ProjectID)
	}
	if meta.IssuanceUnit != prof.TokenUnit {
		return nil, fmt.Errorf("metadata.json issuance.unit %q does not match profile.json tokenUnit %q", meta.IssuanceUnit, prof.TokenUnit)
	}
	if policyProjectID != prof.ProjectID {
		return nil, fmt.Errorf("profile.json projectId %s does not match policy projectId %s", prof.ProjectID, policyProjectID)
	}

	profileDigestHex := "0x" + hex.EncodeToString(prof.Digest[:])
	metadataDigestHex := "0x" + hex.EncodeToString(meta.Digest[:])
	if !strings.EqualFold(policyProfileDigest, profileDigestHex) {
		return nil, fmt.Errorf("recomputed profileDigest %s does not match policy profileDigest %s", profileDigestHex, policyProfileDigest)
	}
	if !strings.EqualFold(profileDigestHex, manifest.ProfileDigest) {
		return nil, fmt.Errorf("recomputed profileDigest %s does not match manifest.json profileDigest %s", profileDigestHex, manifest.ProfileDigest)
	}
	if !strings.EqualFold(metadataDigestHex, manifest.MetadataDigest) {
		return nil, fmt.Errorf("recomputed metadataDigest %s does not match manifest.json metadataDigest %s", metadataDigestHex, manifest.MetadataDigest)
	}

	return &validatedPackage{
		manifest:          manifest,
		profile:           prof,
		metadata:          meta,
		files:             filesExceptManifest,
		profileDigestHex:  profileDigestHex,
		metadataDigestHex: metadataDigestHex,
	}, nil
}
