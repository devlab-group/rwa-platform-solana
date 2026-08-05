package api

import (
	"context"
	"testing"
	"time"

	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
)

const securityStaleTestChainID = 900001

// securityApp builds a minimal App + repos for exercising
// App.securityCheckpoint/toProjectResponse directly, rather than reusing the
// full setupTestApp harness (api_test.go) this doesn't need.
func securityApp(t *testing.T) (*App, *models.Project) {
	t.Helper()
	repos := memory.New()
	p := &models.Project{
		ProjectID: "sol-p1", ChainID: securityStaleTestChainID, Status: models.ProjectStatusActive,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := repos.Projects.Upsert(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	app := &App{
		Repos:             repos,
		ProgramCompliance: "CompLiance111111111111111111111111111111111",
		ProgramVault:      "VauLT1111111111111111111111111111111111111",
	}
	return app, p
}

// TestSecurityCheckpointUsesPerProgramCheckpoint is the regression test
// for the just-fixed checkpoint bug in App.securityCheckpoint (project.go):
// under the old EVM-only lookup (blockchain.CheckpointAddress, the synthetic
// "ALL" row), this deployment — whose indexer only ever writes a
// checkpoint keyed by each program's own address, never "ALL" — would report
// securityStale=true FOREVER, even with a healthy, freshly-reconciled
// indexer. This proves the per-program lookup path fixes that: a per-program
// checkpoint plus a fresh Security.AsOfTime must report stale=false.
func TestSecurityCheckpointUsesPerProgramCheckpoint(t *testing.T) {
	app, p := securityApp(t)
	now := time.Now().UTC()
	if err := app.Repos.IndexerCheckpoints.Set(context.Background(), &models.IndexerCheckpoint{
		ChainID: securityStaleTestChainID, Address: app.ProgramCompliance, LastBlock: 500, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	p.Security = &models.SecurityState{AsOfBlock: 500, AsOfTime: now}
	if err := app.Repos.Projects.Upsert(context.Background(), p); err != nil {
		t.Fatal(err)
	}

	resp := app.toProjectResponse(context.Background(), p)
	if resp.SecurityStale {
		t.Error("SecurityStale = true, want false (this would fail under the old ALL-only checkpoint lookup, which the indexer never writes)")
	}
}

// TestSecurityCheckpointNoCheckpointIsStale: nothing has been scanned
// yet — securityCheckpoint returns ErrNotFound for every configured program
// id, and securityStale treats that as stale regardless of the projection.
func TestSecurityCheckpointNoCheckpointIsStale(t *testing.T) {
	app, p := securityApp(t)
	p.Security = &models.SecurityState{AsOfBlock: 500, AsOfTime: time.Now().UTC()}
	if err := app.Repos.Projects.Upsert(context.Background(), p); err != nil {
		t.Fatal(err)
	}

	resp := app.toProjectResponse(context.Background(), p)
	if !resp.SecurityStale {
		t.Error("SecurityStale = false, want true with no indexer checkpoint at all")
	}
}

// TestSecurityCheckpointStaleAsOfTime: a per-program checkpoint
// exists (the indexer is running), but the governance projection itself has
// fallen behind securityStalenessWindow — a stopped projector, distinct from
// a stopped indexer.
func TestSecurityCheckpointStaleAsOfTime(t *testing.T) {
	app, p := securityApp(t)
	if err := app.Repos.IndexerCheckpoints.Set(context.Background(), &models.IndexerCheckpoint{
		ChainID: securityStaleTestChainID, Address: app.ProgramCompliance, LastBlock: 500, UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	p.Security = &models.SecurityState{AsOfBlock: 400, AsOfTime: time.Now().UTC().Add(-5 * time.Minute)}
	if err := app.Repos.Projects.Upsert(context.Background(), p); err != nil {
		t.Fatal(err)
	}

	resp := app.toProjectResponse(context.Background(), p)
	if !resp.SecurityStale {
		t.Error("SecurityStale = false, want true with a stale AsOfTime")
	}
}
