// Package keys defines the hot-key lifecycle abstraction the compliance
// key's process-shutdown handling wraps around (see
// cmd/platform's complianceKeyCloser): a Provider supports reloading
// key material without a process restart and zeroing it in memory at
// shutdown. The server holds no other hot keys — deployment, minting, and
// every admin/treasury/redemption action is calldata broadcast from the
// connected wallet, never a server-signed transaction — so this package no
// longer owns any key-loading backend of its own; the compliance key
// is loaded directly (see cmd/platform's loadComplianceKey) and only
// wrapped in this interface for its Close() lifecycle hook.
package keys

import "context"

// Provider is a hot key that can reload its key material from its source
// (rotation support) and zero it from memory at shutdown.
type Provider interface {
	// Reload re-reads/re-fetches key material from this Provider's source.
	// Safe to call at any time, including concurrently with normal use.
	Reload(ctx context.Context) error
	// Close zeroes any private key material this Provider holds in memory.
	// Call once, at process shutdown. Best-effort, not a hard security
	// guarantee (the Go runtime may have copied the bytes elsewhere via GC
	// or stack growth before Close runs), but it removes the primary
	// in-memory copy as soon as it's no longer needed.
	Close() error
}
