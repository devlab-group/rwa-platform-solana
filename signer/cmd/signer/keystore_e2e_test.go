package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	rwakeystore "github.com/rwa-platform/signer/internal/keystore"
)

// TestE2E_KeystoreCreate_WritesUsableKeystore covers "signer keystore
// create" end to end: it must write a keystore that internal/keystore.Load
// can decrypt with the operator's chosen password, and it must never print
// the generated private key.
func TestE2E_KeystoreCreate_WritesUsableKeystore(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	workDir := t.TempDir()
	outPath := filepath.Join(workDir, "auditor.json")

	cmd := exec.Command(signerBin, "keystore", "create", "--out", outPath)
	cmd.Stdin = strings.NewReader("a-strong-new-keystore-pw\na-strong-new-keystore-pw\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("keystore create failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	priv, addr, err := rwakeystore.Load(outPath, "a-strong-new-keystore-pw")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer rwakeystore.Zero(priv)

	if !strings.Contains(stdout.String(), addr.Hex()) {
		t.Errorf("expected stdout to report the created address %s, got:\n%s", addr.Hex(), stdout.String())
	}
	privHex := hex.EncodeToString(crypto.FromECDSA(priv))
	if strings.Contains(stdout.String(), privHex) || strings.Contains(stderr.String(), privHex) {
		t.Error("keystore create must never print the private key")
	}
}

func TestE2E_KeystoreCreate_RejectsWeakPassword(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	outPath := filepath.Join(t.TempDir(), "auditor.json")
	cmd := exec.Command(signerBin, "keystore", "create", "--out", outPath)
	cmd.Stdin = strings.NewReader("short\nshort\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("expected keystore create to reject a too-short password")
	}
	if _, err := os.Stat(outPath); err == nil {
		t.Error("keystore file must not be written when the password is rejected")
	}
}

func TestE2E_KeystoreCreate_RejectsMismatchedConfirmation(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	outPath := filepath.Join(t.TempDir(), "auditor.json")
	cmd := exec.Command(signerBin, "keystore", "create", "--out", outPath)
	cmd.Stdin = strings.NewReader("a-strong-new-keystore-pw\na-different-password-9\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("expected keystore create to reject a mismatched password confirmation")
	}
	if !strings.Contains(stderr.String(), "match") {
		t.Errorf("unexpected error, stderr:\n%s", stderr.String())
	}
	if _, err := os.Stat(outPath); err == nil {
		t.Error("keystore file must not be written when confirmation does not match")
	}
}

func TestE2E_KeystoreCreate_RefusesToOverwrite(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	outPath := filepath.Join(t.TempDir(), "auditor.json")
	if err := os.WriteFile(outPath, []byte("not a keystore"), 0o600); err != nil {
		t.Fatalf("writing pre-existing file: %v", err)
	}

	cmd := exec.Command(signerBin, "keystore", "create", "--out", outPath)
	cmd.Stdin = strings.NewReader("a-strong-new-keystore-pw\na-strong-new-keystore-pw\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("expected keystore create to refuse to overwrite an existing file")
	}
	data, err := os.ReadFile(outPath)
	if err != nil || string(data) != "not a keystore" {
		t.Error("existing file must be left untouched when creation is refused")
	}
}

// TestE2E_KeystoreCreate_RefusesToFollowDanglingSymlink guards against
// writing through a symlink at --out. A Stat-then-WriteFile implementation
// would happily follow a symlink there, including a *dangling* one (pointing
// somewhere that does not yet exist), landing the new keystore at whatever
// path the symlink names instead of --out itself. os.O_CREATE|os.O_EXCL must
// refuse this the same way it refuses an ordinary existing file.
func TestE2E_KeystoreCreate_RefusesToFollowDanglingSymlink(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	workDir := t.TempDir()
	target := filepath.Join(workDir, "elsewhere.json") // does not exist
	linkPath := filepath.Join(workDir, "auditor.json")
	if err := os.Symlink(target, linkPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	cmd := exec.Command(signerBin, "keystore", "create", "--out", linkPath)
	cmd.Stdin = strings.NewReader("a-strong-new-keystore-pw\na-strong-new-keystore-pw\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected keystore create to refuse a dangling symlink at --out\nstdout:\n%s", stdout.String())
	}
	if _, err := os.Stat(target); err == nil {
		t.Error("keystore create must not have written through the symlink to its target")
	}
	if _, err := os.Lstat(linkPath); err != nil {
		t.Errorf("the symlink itself should be left in place, untouched: %v", err)
	}
}

// TestE2E_KeystoreImport_RoundTrip covers "signer keystore import":
// encrypting an existing raw private key from an owner-only-readable file
// must produce a keystore that decrypts back to the same key and address.
func TestE2E_KeystoreImport_RoundTrip(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	wantAddr := crypto.PubkeyToAddress(priv.PublicKey)

	workDir := t.TempDir()
	privkeyPath := filepath.Join(workDir, "privkey.hex")
	if err := os.WriteFile(privkeyPath, []byte(hex.EncodeToString(crypto.FromECDSA(priv))+"\n"), 0o600); err != nil {
		t.Fatalf("writing privkey file: %v", err)
	}
	outPath := filepath.Join(workDir, "auditor.json")

	cmd := exec.Command(signerBin, "keystore", "import", "--privkey-file", privkeyPath, "--out", outPath)
	cmd.Stdin = strings.NewReader("a-strong-imported-pw-123\na-strong-imported-pw-123\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("keystore import failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	gotPriv, gotAddr, err := rwakeystore.Load(outPath, "a-strong-imported-pw-123")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer rwakeystore.Zero(gotPriv)
	if gotAddr != wantAddr {
		t.Errorf("address = %s, want %s", gotAddr.Hex(), wantAddr.Hex())
	}
	if gotPriv.D.Cmp(priv.D) != 0 {
		t.Error("imported key does not round-trip")
	}
}

func TestE2E_KeystoreImport_RejectsWorldReadablePrivkeyFile(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	workDir := t.TempDir()
	privkeyPath := filepath.Join(workDir, "privkey.hex")
	if err := os.WriteFile(privkeyPath, []byte(hex.EncodeToString(crypto.FromECDSA(priv))+"\n"), 0o644); err != nil {
		t.Fatalf("writing world-readable privkey file: %v", err)
	}
	outPath := filepath.Join(workDir, "auditor.json")

	cmd := exec.Command(signerBin, "keystore", "import", "--privkey-file", privkeyPath, "--out", outPath)
	cmd.Stdin = strings.NewReader("a-strong-imported-pw-123\na-strong-imported-pw-123\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("expected keystore import to reject a world-readable --privkey-file")
	}
	if !strings.Contains(stderr.String(), "readable") {
		t.Errorf("unexpected error, stderr:\n%s", stderr.String())
	}
	if _, err := os.Stat(outPath); err == nil {
		t.Error("keystore file must not be written when --privkey-file is rejected")
	}
}
