package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/logger"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/migrate"
)

func main() {
	dir := flag.String("dir", "migrations", "directory containing *.up.sql files")
	flag.Parse()

	_ = godotenv.Load()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		logger.Error("DATABASE_URL is required")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	if err := migrate.Run(ctx, dsn, *dir); err != nil {
		logger.Error("migration failed", "err", err)
		os.Exit(1)
	}
	logger.Info("migrations up to date")
}
