package assets

import (
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
)

const (
	gClusterGenesis = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
	gSupplyProgram  = "8sN3xz2XSXo7oJ6VfBJKF4G8VZ7pJZcFmqjWpZBAeZZ5"
	gSupplyConfig   = "3n1LDeUZm2q7NwiWWY6VkFpBEsWc3d2SNAhK6vAj9Fyc"
	gVaultConfig    = "Bswb3UyeD1pUTaGiE6WvqwFpJZsQSEY1xhJePCDTHdvp"
)

func guardService(t *testing.T, auditor common.Address) *RecordService {
	t.Helper()
	repos := memory.New()
	s, err := NewRecordService(repos.AssetRecords, repos.AuditPackages, repos.Attestations, nil,
		gClusterGenesis, gSupplyProgram, gSupplyConfig, gVaultConfig, auditor)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func guardRecord() *models.AssetRecord {
	return &models.AssetRecord{
		RecordID:       "rec-1",
		RecordKey:      "0x" + strings.Repeat("11", 32),
		MetadataDigest: "0x" + strings.Repeat("22", 32),
		Amount:         "1000",
		Nonce:          "1",
		ValidUntil:     0,
	}
}

// TestBuildMintAttestationRefusesZeroAuditor is the guard for a real incident:
// a server started BEFORE the chain was bootstrapped has no auditor to read, so
// every .rwa package it produced carried a ZERO auditor address in
// typed-data.json. Such a package is unsignable (the offline signer's policy
// compares its own auditor against the document's) and unmintable — but it
// looks complete, so the failure only surfaced after the whole offline signing
// round-trip.
func TestBuildMintAttestationRefusesZeroAuditor(t *testing.T) {
	s := guardService(t, common.Address{})

	_, _, err := s.BuildMintAttestation(guardRecord(), [32]byte{})
	if !errors.Is(err, ErrAuditorUnknown) {
		t.Fatalf("err = %v, want ErrAuditorUnknown", err)
	}
	if !strings.Contains(err.Error(), "bootstrapped") {
		t.Error("the error should tell the operator what to check, not just that it failed")
	}
}

// TestSetBaselineAuditorRecoversWithoutRestart: once the auditor becomes
// readable on-chain, package building must start working in the SAME process.
// Before this, ReconcileAuditor's no-event fallback re-asserted the boot-time
// zero on every tick — and since no program's `initialize` emits an
// AuditorChanged event, that state never cleared without a restart.
func TestSetBaselineAuditorRecoversWithoutRestart(t *testing.T) {
	s := guardService(t, common.Address{})
	if _, _, err := s.BuildMintAttestation(guardRecord(), [32]byte{}); !errors.Is(err, ErrAuditorUnknown) {
		t.Fatalf("precondition: err = %v, want ErrAuditorUnknown", err)
	}

	onChain := common.HexToAddress("0x00000000000000000000000000000000000aa11")
	s.SetBaselineAuditor(onChain)

	doc, _, err := s.BuildMintAttestation(guardRecord(), [32]byte{})
	if err != nil {
		t.Fatalf("BuildMintAttestation after the auditor became readable: %v", err)
	}
	if !strings.EqualFold(doc.Message.Auditor, onChain.Hex()) {
		t.Errorf("typed-data auditor = %q, want %q", doc.Message.Auditor, onChain.Hex())
	}
}

// TestSetBaselineAuditorDoesNotOverrideALiveRotation: the on-chain baseline is
// a FALLBACK. A rotation already applied from an AuditorChanged event must not
// be clobbered by the (older) config-account read on the next tick.
func TestSetBaselineAuditorDoesNotOverrideALiveRotation(t *testing.T) {
	s := guardService(t, common.HexToAddress("0x00000000000000000000000000000000000a001"))
	rotated := common.HexToAddress("0x00000000000000000000000000000000000b002")
	s.SetAuditor(rotated)

	s.SetBaselineAuditor(common.HexToAddress("0x00000000000000000000000000000000000c003"))

	doc, _, err := s.BuildMintAttestation(guardRecord(), [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(doc.Message.Auditor, rotated.Hex()) {
		t.Errorf("typed-data auditor = %q, want the rotated %q — the baseline must not override a live value", doc.Message.Auditor, rotated.Hex())
	}
}
