package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var DBPOOL *pgxpool.Pool

func Connect(dsn string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return err
	}

	config.MaxConns = 25
	config.MinConns = 5
	config.MaxConnLifetime = 5 * time.Minute
	config.MaxConnIdleTime = 2 * time.Minute

	dbpool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return err
	}

	err = dbpool.Ping(ctx)
	if err != nil {
		dbpool.Close()
		return err
	}

	DBPOOL = dbpool

	return nil
}
