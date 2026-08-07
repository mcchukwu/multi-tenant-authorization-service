package main

import (
	"context"
	"multi-tenant-authorization-service/pkg/config"
	"multi-tenant-authorization-service/pkg/db"
	"multi-tenant-authorization-service/pkg/logger"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// Load and validate configuration
	cfg := config.Load()
	if err := config.Validate(cfg); err != nil {
		logger.Error("Invalid configuration: %s", err.Error())
		os.Exit(1)
	}

	// Create a new HTTP router
	mux := http.NewServeMux()

	// Connect to database
	if err := db.Connect(cfg.DBURL); err != nil {
		logger.Error("Failed to connect to database")
		os.Exit(1)
	}
	logger.Info("Connected to database")

	// Start server safely
	server := &http.Server{
		Addr:         ":" + cfg.AppPort,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	go func() {
		logger.Info("Server is running on port %s", cfg.AppPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Failed to start server")
			os.Exit(1)
		}
	}()

	// Shutdown signal listener
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Graceful shutdown context
	logger.Info("Shutting down server")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		logger.Error("Graceful shutdown failed")
		server.Close()
	}

	// Close database connection
	logger.Info("Closing database connection")
	if err := db.DB.Close(); err != nil {
		logger.Error("Failed to close database connection")
	}
	logger.Info("Database connection closed")

	logger.Info("Server is exiting gracefully")
}
