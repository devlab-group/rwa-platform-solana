// Package project holds the platform's single Asset Profile-bound project
// record and the deployment-observation/verification logic that
// adopts and verifies it (see security.go and seed.go). The
// server holds no deployer key: deployment is broadcast by the admin's own
// wallet/tooling, and this package only reads the chain and the DB.
package project

import (
	"context"

	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
)

// Service exposes the stored project record.
type Service struct {
	repo repository.ProjectRepository
}

// New constructs a Service over repo.
func New(repo repository.ProjectRepository) *Service {
	return &Service{repo: repo}
}

// GetProject returns the current project record.
func (s *Service) GetProject(ctx context.Context) (*models.Project, error) {
	return s.repo.Get(ctx)
}
