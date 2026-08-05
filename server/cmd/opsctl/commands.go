package main

// Command implementations: the audited operator commands for IPFS
// replication retry and local restore. Every function here is deliberately
// shaped to take already-constructed dependencies (a repository.Repositories,
// an *ipfs.ReplicationManager) and write human-readable progress to an
// io.Writer, rather than reading flags or touching os.Stdout/os.Exit
// directly — main.go owns process wiring (config, Mongo connection, flag
// parsing) so these can be smoke tested directly against in-memory repos and
// fakes (commands_test.go), the same split cmd/reindex's snapshotCounts uses
// for its one helper.

import (
	"context"
	"fmt"
	"io"

	"github.com/rwa-platform/server/internal/auditlog"
	"github.com/rwa-platform/server/internal/dal/repository"
	"github.com/rwa-platform/server/internal/ipfs"
)

// opsCtx bundles what every command needs to run and to audit-log its own
// invocation.
type opsCtx struct {
	ctx   context.Context
	repos *repository.Repositories
	audit *auditlog.Logger
	// actor is the attributable audit label for this invocation (main.go's
	// auditActor sets it to "opsctl:"+the --actor flag or OS user). opsctl is
	// not credential-gated, so this is for attribution only, not authorization.
	actor string
	out   io.Writer
}

// audited runs op (the actual mutation) wrapped in the
// intent-before-effect / fail-closed pattern: it first persists a durable
// audit INTENT and, if that cannot be made durable, REFUSES to run op at all
// (a privileged replication mutation with no durable actor/action trail is
// worse than not running it). After op it records a completion linked to
// that intent, capturing success/failure — a failure to write the RESULT is
// only a warning, since the intent already durably captured who invoked
// what. This supersedes the old "run op, then best-effort append one entry"
// flow, which recorded nothing until AFTER the mutation and only warned on
// an audit failure (fail-open).
func (o opsCtx) audited(action, target string, metadata map[string]any, op func() error) error {
	intentID, err := o.audit.RecordIntent(o.ctx, "opsctl", o.actor, action, target, metadata)
	if err != nil {
		fmt.Fprintf(o.out, "ERROR: refusing to run %s %s — its audit intent could not be made durable: %v\n", action, target, err)
		return fmt.Errorf("opsctl: audit intent for %s %s could not be persisted; refusing to proceed: %w", action, target, err)
	}

	opErr := op()

	resultMeta := map[string]any{}
	if opErr != nil {
		resultMeta["error"] = opErr.Error()
	}
	if auditErr := o.audit.RecordResult(o.ctx, intentID, "opsctl", o.actor, action, target, opErr == nil, resultMeta); auditErr != nil {
		fmt.Fprintf(o.out, "WARNING: audit result write failed for %s %s: %v\n", action, target, auditErr)
	}
	return opErr
}

// --- ipfs replication ---

func runIPFSRetry(o opsCtx, rm *ipfs.ReplicationManager, id string, data []byte) error {
	return o.audited("ipfs.retry", id, map[string]any{"bytes": len(data)}, func() error {
		if err := rm.Retry(o.ctx, id, data); err != nil {
			return err
		}
		fmt.Fprintf(o.out, "%s: replication retry complete\n", id)
		return nil
	})
}

func runIPFSRestoreLocal(o opsCtx, rm *ipfs.ReplicationManager, id string) error {
	return o.audited("ipfs.restoreLocal", id, nil, func() error {
		if err := rm.RestoreLocal(o.ctx, id); err != nil {
			return err
		}
		fmt.Fprintf(o.out, "%s: local copy restored from a backup destination\n", id)
		return nil
	})
}
