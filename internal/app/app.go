package app

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/config"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/db"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/logger"
)

type App struct {
	server *http.Server
	db     *pgxpool.Pool
}

func New(cfg *config.Config) (*App, error) {
	pool, err := db.Connect(cfg.DBURL)
	if err != nil {
		return nil, err
	}

	logger.Info("Connected to database")

	mux := http.NewServeMux()

	v1 := http.NewServeMux()
	v1.Handle("/api/v1/", http.StripPrefix("/api/v1", mux))

	server := &http.Server{
		Addr:    ":" + cfg.AppPort,
		Handler: v1,
	}

	return &App{
		server: server,
		db:     pool,
	}, nil
}

func (a *App) Start() error {
	go func() {
		logger.Info("Server is running")

		err := a.server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Server failed to start")
		}
	}()

	return nil
}

func (a *App) Shutdown(ctx context.Context) error {
	logger.Info("Application shutdown started")

	// Stop accepting new HTTP requests and wait for active requests to finish
	if err := a.server.Shutdown(ctx); err != nil {
		return err
	}

	logger.Info("Server stopped")

	// The HTTP server has finished, so nothing should still be using the database through HTTP handlers.
	a.db.Close()

	logger.Info("Database closed")
	logger.Info("Application shutdown completed")

	return nil
}
