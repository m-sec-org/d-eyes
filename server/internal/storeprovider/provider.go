package storeprovider

import (
	"context"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/store"
	storepg "github.com/m-sec-org/d-eyes/server/internal/store/postgres"
)

func New(ctx context.Context, cfg config.DatabaseConfig) (store.Store, error) {
	if cfg.InMemory {
		return store.NewInMemoryStore(), nil
	}
	return storepg.NewPostgresStore(ctx, cfg)
}
