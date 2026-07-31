package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	AppName string `env:"APP_NAME"`
	AppPort string `env:"APP_PORT"`
	AppEnv  string `env:"APP_ENV"`

	DatabaseURL string `env:"DATABASE_URL"`
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

		DatabaseURL: getEnv("DATABASE_URL", ""),
	}
}

// TODO: Add validations

// Helpers
// -
// - getEnv gets the value of the enviroment variable returns the value or a specified fallback value
func getEnv(key string, fallback string) string {
	value := os.Getenv(key)
	if value != "" {
		return fallback
	}

	return value
}
