package config

import (
	"errors"
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	AppName string `env:"APP_NAME"`
	AppPort string `env:"APP_PORT"`
	AppEnv  string `env:"APP_ENV"`
	DBURL   string `env:"DATABASE_URL"`
}

// Load loads the configuration from the environment variables and returns the configuration struct
func Load() *Config {
	if err := godotenv.Load(); err != nil {
		log.Fatal(".env file not found")
	}

	return &Config{
		AppName: getEnv("APP_NAME", "[app name]"),
		AppPort: getEnv("APP_PORT", "8080"),
		AppEnv:  getEnv("APP_ENV", "development"),
		DBURL:   getEnv("DB_URL", ""),
	}
}

func Validate(c *Config) error {
	if c.AppName == "" {
		return errors.New("app name is required")
	}

	if c.AppPort == "" {
		return errors.New("app port is required")
	}

	if c.AppEnv != "production" && c.AppEnv != "development" {
		return errors.New("invalid app env")
	}

	if c.DBURL == "" {
		return errors.New("database url is required")
	}

	return nil
}

// -
// Helpers
// -
// getEnv() gets the value of the enviroment variable key returns the value or a specified fallback value
func getEnv(key string, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	return value
}
