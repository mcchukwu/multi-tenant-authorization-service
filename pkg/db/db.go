package db

import (
	"context"
	"database/sql"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

var DB *sql.DB

// Connect() takes a database connection string and opens a connection to the database, returning an error if there is a problem
func Connect(dsn string) error {
	database, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}

	database.SetMaxOpenConns(25)
	database.SetMaxIdleConns(25)
	database.SetConnMaxLifetime(5 * time.Minute)
	database.SetConnMaxIdleTime(2 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := database.PingContext(ctx); err != nil {
		return err
	}

	DB = database

	return nil
}
