package project

import (
	"context"
	"testing"

	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
)

func TestServiceGetProjectNotFound(t *testing.T) {
	svc := New(memory.NewProjectRepository())
	if _, err := svc.GetProject(context.Background()); err != repository.ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestServiceGetProjectReturnsStored(t *testing.T) {
	repo := memory.NewProjectRepository()
	if err := repo.Upsert(context.Background(), &models.Project{ProjectID: "proj-1", Status: models.ProjectStatusActive}); err != nil {
		t.Fatal(err)
	}
	svc := New(repo)
	got, err := svc.GetProject(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.ProjectID != "proj-1" || got.Status != models.ProjectStatusActive {
		t.Errorf("got %+v", got)
	}
}
