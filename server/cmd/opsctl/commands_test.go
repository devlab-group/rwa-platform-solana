package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/rwa-platform/server/internal/auditlog"
	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
	"github.com/rwa-platform/server/internal/ipfs"
)

func testOpsCtx(repos *repository.Repositories) opsCtx {
	return opsCtx{
		ctx: context.Background(), repos: repos, audit: auditlog.New(repos.AuditLogs),
		actor: "opsctl:test", out: &bytes.Buffer{},
	}
}

func newTestRepos() *repository.Repositories { return memory.New() }

// TestRunIPFSRetry is a smoke test: a backup destination that has
// never seen the content gets it added and pinned, and the publication
// record's state advances to Replicated once the configured threshold is
// met.
func TestRunIPFSRetry(t *testing.T) {
	repos := newTestRepos()
	ctx := context.Background()
	data := []byte(`{"asset":"opsctl-retry-test"}`)
	cid, err := ipfs.ComputeCIDv1Raw(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := repos.Publications.Upsert(ctx, &models.PublicationRecord{
		ID: "pub-1", CID: cid, State: models.PublicationReplicationPending, ReplicationThreshold: 1,
	}); err != nil {
		t.Fatal(err)
	}

	local := ipfs.NewFakeClient()
	backup := ipfs.NewFakeClient()
	rm := ipfs.NewReplicationManager(local, []ipfs.Destination{{Name: "backup", Client: backup}}, 1, repos.Publications)

	o := testOpsCtx(repos)
	if err := runIPFSRetry(o, rm, "pub-1", data); err != nil {
		t.Fatalf("runIPFSRetry: %v", err)
	}
	rec, err := repos.Publications.Get(ctx, "pub-1")
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != models.PublicationReplicated {
		t.Fatalf("State = %s, want Replicated", rec.State)
	}
}

// TestRunIPFSRestoreLocal is a smoke test: content present on a
// backup but missing locally is restored to the local client.
func TestRunIPFSRestoreLocal(t *testing.T) {
	repos := newTestRepos()
	ctx := context.Background()
	data := []byte(`{"asset":"opsctl-restore-test"}`)

	backup := ipfs.NewFakeClient()
	cid, err := backup.AddRaw(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := repos.Publications.Upsert(ctx, &models.PublicationRecord{
		ID: "pub-2", CID: cid, State: models.PublicationReplicationFailed, ReplicationThreshold: 1,
	}); err != nil {
		t.Fatal(err)
	}

	local := ipfs.NewFakeClient()
	rm := ipfs.NewReplicationManager(local, []ipfs.Destination{{Name: "backup", Client: backup}}, 1, repos.Publications)

	o := testOpsCtx(repos)
	if err := runIPFSRestoreLocal(o, rm, "pub-2"); err != nil {
		t.Fatalf("runIPFSRestoreLocal: %v", err)
	}
	if _, err := local.Get(ctx, cid); err != nil {
		t.Fatalf("expected the content to be restored to the local client: %v", err)
	}
}

// TestAuditActor pins that the audit-actor label is attributable and
// "opsctl:"-prefixed: an explicit --actor wins, and it never falls through to
// an empty label (opsctl is not credential-gated — this is attribution only).
func TestAuditActor(t *testing.T) {
	if got := auditActor("alice"); got != "opsctl:alice" {
		t.Errorf("auditActor(alice) = %q, want opsctl:alice", got)
	}
	if got := auditActor("  spaced  "); got != "opsctl:spaced" {
		t.Errorf("auditActor trims whitespace: got %q", got)
	}
	// With no flag, it derives from the OS user or falls back to "opsctl";
	// either way the label is non-empty and prefixed.
	got := auditActor("")
	if got == "opsctl:" || len(got) <= len("opsctl:") {
		t.Errorf("auditActor(\"\") = %q, want a non-empty opsctl:<label>", got)
	}
}
