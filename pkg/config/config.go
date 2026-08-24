package config

import (
	"errors"
	"os"

	"github.com/joho/godotenv"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/logger"
)

// Create a configuration struct
type Config struct {
	AppName string `env:"APP_NAME"`
	AppPort string `env:"APP_PORT"`
	AppEnv  string `env:"APP_ENV"`
	DBURL   string `env:"DB_URL"`
}

// Load() loads the configuration from the environment variables and returns the configuration struct
func Load() *Config {
	err := godotenv.Load()
	if err != nil {
		logger.Error("Failed to load environment variables")
	}

	return &Config{
		AppName: getEnv("APP_NAME", ""),
		AppPort: getEnv("APP_PORT", ""),
		AppEnv:  getEnv("APP_ENV", ""),
		DBURL:   getEnv("DB_URL", ""),
	}
}

// Validate() validates the configuration struct
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
