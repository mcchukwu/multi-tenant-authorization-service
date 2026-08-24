package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mcchukwu/multi-tenant-authorization-service/internal/app"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/config"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/logger"
)

func main() {
	// Load and validate configuration
	cfg := config.Load()
	if err := config.Validate(cfg); err != nil {
		logger.Error("Invalid configuration")
		os.Exit(1)
	}

	// Create application
	application, err := app.New(cfg)
	if err != nil {
		logger.Error("Failed to create application")
		os.Exit(1)
	}

	// Start application
	if err := application.Start(); err != nil {
		logger.Error("Failed to start application")
		os.Exit(1)
	}

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(quit)

	<-quit

	// Start graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := application.Shutdown(shutdownCtx); err != nil {
		logger.Error("Application shutdown failed")
		os.Exit(1)
	}

	logger.Info("Application stopped")
}
