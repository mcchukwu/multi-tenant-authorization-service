package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mcchukwu/multi-tenant-authorization-service/internal/audit"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/auth"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/health"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/config"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/db"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/logger"
)

func main() {
	// Configuration
	cfg := config.Load()
	if err := config.Validate(cfg); err != nil {
		logger.Error("Invalid configuration")
		os.Exit(1)
	}

	// Infrastructure
	dbPool, err := db.Connect(cfg.DBURL)
	if err != nil {
		logger.Error("Failed to connect to database")
		os.Exit(1)
	}
	logger.Info("Connected to database")

	// Dependencies
	healthHandler := health.NewHandler(dbPool)

	auditRepo := audit.NewRepository(dbPool)
	auditService := audit.NewService(auditRepo)

	authRepo := auth.NewRepository(dbPool)
	authService := auth.NewService(authRepo, auditService, cfg, dbPool)
	authHandler := auth.NewHandler(authService, cfg)

	// Routing
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", healthHandler.Health)
	mux.HandleFunc("GET /health/live", healthHandler.Live)
	mux.HandleFunc("GET /health/ready", healthHandler.Ready)

	mux.Handle("POST /auth/login", http.HandlerFunc(authHandler.Login))
	mux.Handle("POST /auth/register", http.HandlerFunc(authHandler.Register))
	mux.Handle("POST /auth/refresh", http.HandlerFunc(authHandler.Refresh))

	v1 := http.NewServeMux()
	v1.Handle("/v1/", http.StripPrefix("/v1", mux))

	// Server
	server := &http.Server{
		Addr:    ":" + cfg.AppPort,
		Handler: v1,
	}

	// Start Server
	serverErr := make(chan error, 1)
	go func() {
		logger.Info("Server is running...")
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	healthHandler.SetReady(true)
	logger.Info("Application is ready")

	// Wait for shutdown signal
	shutdownSignal := make(chan os.Signal, 1)
	signal.Notify(shutdownSignal, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(shutdownSignal)

	select {
	case <-shutdownSignal:
		healthHandler.SetReady(false)
	case <-serverErr:
		logger.Error("Server failed to start")
		os.Exit(1)
	}

	// Start graceful shutdown
	logger.Info("Application shutdown started")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Stop accepting new HTTP requests and wait for active requests to finish
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("Server failed to shutdown")
		os.Exit(1)
	}
	logger.Info("Server stopped")

	// The HTTP server has finished, so nothing should still be using the database through HTTP handlers.
	dbPool.Close()
	logger.Info("Database closed")
	logger.Info("Application shutdown completed")
	logger.Info("Application stopped")
}
