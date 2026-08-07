package db

import (
	"context"
	"database/sql"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

var DB *sql.DB

// Connect() validates a data source name and assigns a connection pool manager
func Connect(dsn string) error {
	database, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}

	// Set connection pool settings
	database.SetMaxOpenConns(25)
	database.SetMaxIdleConns(25)
	database.SetConnMaxLifetime(5 * time.Minute)
	database.SetConnMaxIdleTime(2 * time.Minute)

	// Ping the database to ensure it is available
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := database.PingContext(ctx); err != nil {
		database.Close()
		return err
	}

	// Assign the database connection pool manager
	DB = database

	return nil
}
