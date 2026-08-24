package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/config"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/db"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/logger"
)

func main() {
	// Load and validate configuration
	cfg := config.Load()
	err := config.Validate(cfg)
	if err != nil {
		logger.Error("Invalid configuration")
		os.Exit(1)
	}

	// Connect to database
	if err := db.Connect(cfg.DBURL); err != nil {
		logger.Error("Failed to connect to database")
		os.Exit(1)
	}
	logger.Info("Connected to database")

	// Create routes routes
	mux := http.NewServeMux()

	// Versioned API
	v1 := http.NewServeMux()
	v1.Handle("/api/v1/", http.StripPrefix("/api/v1", mux))

	// Start server in a goroutine
	server := http.Server{
		Addr:    ":" + cfg.AppPort,
		Handler: v1,
	}

	go func() {
		logger.Info("Server is running")
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Failed to start server")
		}
	}()

	// Wait to receive shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Start graceful shutdown
	logger.Info("Graceful shutdown started")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err = server.Shutdown(ctx)
	if err != nil {
		logger.Error("Graceful shutdown failed")
		os.Exit(1)
	}

	// Close database connection
	db.DBPOOL.Close()
	logger.Info("Database closed")

	logger.Info("Server stopped")
}
