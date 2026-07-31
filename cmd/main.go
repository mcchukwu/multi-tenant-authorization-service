package main

import (
	"fmt"
	"multi-tenant-authorization-service/pkg/config"
	"multi-tenant-authorization-service/pkg/db"
	"multi-tenant-authorization-service/pkg/logger"
	"net/http"
	"os"
)

func main() {
	cfg := config.Load()

	mux := http.NewServeMux()

	// Connect to database
	if err := db.Connect(cfg.DatabaseURL); err != nil {
		logger.Error("Failed to connect to database")
		os.Exit(1)
	}
	logger.Info("Connected to database")

	// Start server
	logger.Info("Starting server")
	if err := http.ListenAndServe(fmt.Sprintf(":%s", cfg.AppPort), mux); err != nil {
		logger.Error("Failed to start server")
		os.Exit(1)
	}
}

