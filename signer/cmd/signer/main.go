// Command signer is the air-gapped CLI auditor tool: it validates a .rwa
// audit package end-to-end and produces a signed-result-solana.json. It
// never makes a network request while signing.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/rwa-platform/signer/internal/attestation"
	"github.com/rwa-platform/signer/internal/hardware"
	"github.com/rwa-platform/signer/internal/keystore"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "sign":
		if err := runSign(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "signer: error:", err)
			os.Exit(1)
		}
	case "keystore":
		if err := runKeystoreCmd(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "signer: error:", err)
			os.Exit(1)
		}
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "signer: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: signer sign <package.rwa> --keystore <path> --policy <path> [--typed-data <path>] [flags]
       signer keystore <create|import> --out <path> [flags]

Air-gapped .rwa audit package review and auditor-attestation signing tool.
Makes zero network requests.

  sign          Signs the keccak attestation bound to (cluster, program,
                config PDA) that the rwa-supply-controller program verifies with
                secp256k1_recover. Writes signed-result-solana.json with a
                64-byte compact [R||S] signature and a separate recoveryId,
                canonical low-S.

Flags:
  --keystore <path>          password-encrypted keystore file (required unless --hardware); accepts
                              either a standard Ethereum V3 JSON keystore or this signer's own
                              Argon2id-based format (internal/keystore), auto-detected
  --password <password>      DEPRECATED, INSECURE: keystore password on the command line, visible in
                              process listings and shell history. Prefer --password-file or the
                              interactive prompt. May be removed in a future version.
  --password-file <path>     file containing the keystore password (first line, trailing newline
                              trimmed). The file must not be group- or world-readable.
  --hardware <device>        sign with a hardware-wallet/HSM adapter instead of a keystore file;
                              <device> is one of: ledger, trezor, yubikey, hsm. No device has a
                              working integration in this V1 build (see internal/hardware and
                              see internal/hardware) -- this always errors
                              today, but is the recommended production signing path once wired up.
  --out <path>                output path for the signed result (default: <package-dir>/
                              signed-result-solana.json)
  --policy <path>            REQUIRED. Independently-provisioned deployment trust root (JSON):
                              cluster, program, config, vault (base58), auditor, projectId,
                              profileDigest, and an optional maxAttestationLifetimeHours. Every
                              value must match the package or the signer refuses to sign -- see
                              internal/policy and docs/auditor/auditor-guide.md.
  --typed-data <path>        OPTIONAL: the Solana attestation request JSON (chain:"solana",
                              primaryType, domain{name,version,cluster,program,config},
                              message{...}) -- the same document a Solana deployment's .rwa
                              package now carries as its own typed-data.json entry. Defaults to
                              the package's own typed-data.json entry when omitted; if given
                              alongside a package that also has one, the two must match
                              byte-for-byte. Every field in it is either recomputed from the
                              package or checked against --policy before signing.
  --yes                      skip the interactive confirmation prompt. Requires --unsafe-test-mode.
  --unsafe-test-mode         required alongside --yes; noninteractive signing removes the human
                              confirmation step and is restricted to scripted test/CI use. --policy
                              is still fully enforced even with this flag -- it never permits signing
                              from package-supplied values alone. It also relaxes the keystore
                              audit-log write failures below from fail-closed to warn-and-continue.
  --audit-anchor <path>      path to the keystore's independent audit-log anchor (default:
                              <keystore>.auditlog.anchor.jsonl, next to the keystore file). Every
                              unlock/sign verifies the keystore's audit log against this anchor
                              before proceeding and refuses to continue if it detects truncation or
                              rewritten history. Point this at separate media (a different mounted
                              drive) for real protection -- an anchor on the same disk as the
                              keystore cannot resist an attacker who can write to that disk. See
                              docs/auditor/auditor-guide.md §5.

Run "signer keystore --help" for the keystore-creation subcommand.`)
}

type signFlags struct {
	keystorePath string
	password     string
	passwordFile string
	hardware     string
	out          string
	policyPath   string
	// typedDataPath is the Solana attestation request: it travels alongside
	// the .rwa package rather than inside it, because the package manifest
	// schema is frozen to three documents plus proofs/ (see
	// typeddata.go).
	typedDataPath  string
	yes            bool
	unsafeTestMode bool
	auditAnchor    string
}

// signDigest signs digest using either a keystore key or a hardware
// adapter, per f, and returns the signature and the recovered signer
// address.
func signDigest(digest common.Hash, f signFlags) ([]byte, common.Address, error) {
	if f.hardware != "" {
		hw, err := hardware.Open(hardware.DeviceKind(f.hardware))
		if err != nil {
			return nil, common.Address{}, err
		}
		defer hw.Close()
		addr, err := hw.Address()
		if err != nil {
			return nil, common.Address{}, fmt.Errorf("hardware-wallet signing (%s) is not implemented in this V1 build (see internal/hardware): %w", f.hardware, err)
		}
		sig, err := hw.SignDigest(digest)
		if err != nil {
			return nil, common.Address{}, fmt.Errorf("hardware-wallet signing (%s): %w", f.hardware, err)
		}
		return sig, addr, nil
	}

	anchorPath := f.auditAnchor
	if anchorPath == "" {
		anchorPath = keystore.DefaultAnchorPath(f.keystorePath)
	}
	// Verify the WHOLE audit chain -- not just that the last append succeeded
	// -- before this process unlocks or signs anything against this keystore.
	// A broken or (if --audit-anchor points at genuinely separate media)
	// truncated log is itself evidence of tampering; signing anyway would
	// extend an audit trail that can no longer be trusted to reflect a
	// complete history.
	if err := keystore.VerifyAuditLogAnchored(f.keystorePath, anchorPath); err != nil {
		return nil, common.Address{}, fmt.Errorf("audit log integrity check failed, refusing to unlock or sign against this keystore: %w", err)
	}

	// A locked-out keystore must be rejected before any password is read or a
	// decrypt is even attempted -- checking after prompting would let an
	// operator (or a script) burn a real attempt against the file during the
	// lockout window.
	if err := keystore.CheckThrottle(f.keystorePath); err != nil {
		return nil, common.Address{}, err
	}

	// --password puts the keystore password in process listings (ps, /proc)
	// and shell history for the life of the shell session. It cannot be
	// zeroized -- by the time this process sees it, it is already a copy owned
	// by the OS/shell -- so it stays deprecated rather than removed outright
	// (some scripted deployments still depend on it), but every use is loudly
	// flagged.
	password := f.password
	if password != "" {
		fmt.Fprintln(os.Stderr, "signer: WARNING: --password exposes the keystore password via process listings and shell history; prefer --password-file or the interactive prompt. This flag is deprecated and may be removed in a future version.")
	}

	if password == "" && f.passwordFile != "" {
		if err := checkPasswordFilePermissions(f.passwordFile); err != nil {
			return nil, common.Address{}, err
		}
		data, err := os.ReadFile(f.passwordFile)
		if err != nil {
			return nil, common.Address{}, fmt.Errorf("reading --password-file: %w", err)
		}
		trimmed := bytes.TrimRight(data, "\r\n")
		password = string(trimmed)
		keystore.ZeroBytes(data) // data and trimmed share a backing array
	}
	if password == "" {
		pw, err := readPassword(os.Stdin)
		if err != nil {
			return nil, common.Address{}, fmt.Errorf("reading password: %w", err)
		}
		password = string(pw)
		keystore.ZeroBytes(pw)
	}

	priv, addr, err := keystore.Load(f.keystorePath, password)
	if err != nil {
		// Every failed unlock attempt counts toward the lockout and is
		// recorded in the tamper-evident audit log, including a KDF-policy or
		// file-permission rejection -- those are just as much a signal of an
		// attacker probing the file as a wrong password would be. This
		// particular pair (throttle/audit for a failed attempt) stays
		// warn-and-continue even in production: the substantive failure below
		// is already returned to the caller, so there is no "operation
		// succeeded but wasn't recorded" gap here -- the fail-closed rule is
		// about the success-path writes below, not this one.
		if throttleErr := keystore.RecordUnlockFailure(f.keystorePath); throttleErr != nil {
			fmt.Fprintln(os.Stderr, "signer: WARNING: failed to record unlock failure for throttling:", throttleErr)
		}
		if auditErr := keystore.AppendAuditEventTo(f.keystorePath, anchorPath, "unlock_failure", map[string]string{"reason": err.Error()}); auditErr != nil {
			fmt.Fprintln(os.Stderr, "signer: WARNING: failed to append unlock-failure audit event:", auditErr)
		}
		return nil, common.Address{}, fmt.Errorf("loading keystore: %w", err)
	}
	defer keystore.Zero(priv)

	// Fail closed in production for the writes on this success path. Unlike
	// the failure path above, silently continuing here means the sensitive
	// operation (unlock, then a signature) proceeds with no durable record of
	// it -- exactly the audit-trail-fails-open trap. --unsafe-test-mode is this
	// signer's existing, already-required marker for "restricted to scripted
	// test/CI use" (main.go's --yes gate), so it doubles as the fail-open
	// escape hatch for exactly that use case; every other invocation fails
	// closed.
	auditFailure := func(step string, err error) error {
		return fmt.Errorf("recording %s to the audit trail failed, refusing to continue without a durable record: %w", step, err)
	}

	if err := keystore.RecordUnlockSuccess(f.keystorePath); err != nil {
		if !f.unsafeTestMode {
			return nil, common.Address{}, auditFailure("throttle-clear", err)
		}
		fmt.Fprintln(os.Stderr, "signer: WARNING (--unsafe-test-mode): failed to clear unlock-throttle state:", err)
	}
	if err := keystore.AppendAuditEventTo(f.keystorePath, anchorPath, "unlock_success", map[string]string{"address": addr.Hex()}); err != nil {
		if !f.unsafeTestMode {
			return nil, common.Address{}, auditFailure("unlock-success", err)
		}
		fmt.Fprintln(os.Stderr, "signer: WARNING (--unsafe-test-mode): failed to append unlock-success audit event:", err)
	}

	sig, err := attestation.Sign(digest, priv)
	if err != nil {
		return nil, common.Address{}, fmt.Errorf("signing: %w", err)
	}
	if err := keystore.AppendAuditEventTo(f.keystorePath, anchorPath, "signed", map[string]string{"address": addr.Hex(), "digest": digest.Hex()}); err != nil {
		if !f.unsafeTestMode {
			// The signature was computed but is deliberately discarded here:
			// per this signer's existing invariant ("any failure at any step
			// exits non-zero and writes nothing," README), a signature that
			// cannot be durably recorded as having been produced must never
			// reach output.Write.
			return nil, common.Address{}, auditFailure("signed", err)
		}
		fmt.Fprintln(os.Stderr, "signer: WARNING (--unsafe-test-mode): failed to append signed audit event:", err)
	}
	return sig, addr, nil
}

// checkPasswordFilePermissions rejects a --password-file that is group- or
// world-readable: such a file leaks the keystore password to any other local
// account, defeating the point of using a file instead of a command-line
// argument.
func checkPasswordFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat --password-file %s: %w", path, err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("--password-file %s is group- or world-readable (mode %s); refusing to read it -- run: chmod 600 %s", path, info.Mode().Perm(), path)
	}
	return nil
}

// readPassword reads a keystore password from stdin, suppressing terminal
// echo via golang.org/x/term when stdin is an interactive terminal.
func readPassword(stdin *os.File) ([]byte, error) {
	return readPasswordPrompt(stdin, newStdinLineReader(stdin), "Keystore password: ")
}

// stdinLineReader wraps a single, shared bufio.Reader over stdin for the
// non-terminal fallback path. It must be created once and reused across
// every readPasswordPrompt call in a process: bufio.Reader reads ahead in
// chunks, so creating a fresh one per call (as an earlier version of this
// function did) can silently swallow a second piped line into a buffer
// that gets discarded when that call returns -- exactly the failure mode
// that would break "signer keystore create"'s two-prompt (password +
// confirmation) piped-stdin tests.
func newStdinLineReader(stdin *os.File) *bufio.Reader {
	return bufio.NewReader(stdin)
}

// readPasswordPrompt is readPassword generalized to a caller-supplied
// prompt and a shared line reader, so "signer keystore create"/"import" can
// ask for a new password twice (with distinct prompts) against the same
// underlying stdin stream. When stdin is not a terminal -- piped input
// from a script or test harness -- there is no echo to suppress, so it
// falls back to a plain line read via br; term.ReadPassword itself would
// simply fail on a non-tty file descriptor.
func readPasswordPrompt(stdin *os.File, br *bufio.Reader, prompt string) ([]byte, error) {
	fmt.Fprint(os.Stdout, prompt)
	if term.IsTerminal(int(stdin.Fd())) {
		pw, err := term.ReadPassword(int(stdin.Fd()))
		fmt.Fprintln(os.Stdout) // ReadPassword swallows the operator's Enter keystroke
		return pw, err
	}
	line, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, err
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}
