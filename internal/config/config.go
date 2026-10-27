package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	AppName            string
	AppPort            string
	AppEnv             string
	DBURL              string
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
	CORSAllowedOrigins []string
}

// Load reads configuration from the environment and refuses to start on
// anything it cannot use. A zero TTL or an empty origin list is a
// misconfiguration, not a default.
func Load() (*Config, error) {
	// A .env file is a local convenience. In a deployed environment the
	// variables are already set, so a missing file is not an error.
	_ = godotenv.Load()

	accessTTL, err := durationEnv("ACCESS_TOKEN_TTL", "15m")
	if err != nil {
		return nil, err
	}
	refreshTTL, err := durationEnv("REFRESH_TOKEN_TTL", "720h")
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		AppName:            getEnv("APP_NAME", ""),
		AppPort:            getEnv("APP_PORT", ""),
		AppEnv:             getEnv("APP_ENV", ""),
		DBURL:              getEnv("DATABASE_URL", ""),
		AccessTokenTTL:     accessTTL,
		RefreshTokenTTL:    refreshTTL,
		CORSAllowedOrigins: splitList(getEnv("CORS_ALLOWED_ORIGINS", "")),
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	switch {
	case c.AppName == "":
		return errors.New("APP_NAME is required")
	case c.AppPort == "":
		return errors.New("APP_PORT is required")
	case c.AppEnv != "production" && c.AppEnv != "development":
		return fmt.Errorf("APP_ENV must be production or development, got %q", c.AppEnv)
	case c.DBURL == "":
		return errors.New("DATABASE_URL is required")
	case len(c.CORSAllowedOrigins) == 0:
		return errors.New("CORS_ALLOWED_ORIGINS is required")
	}
	return nil
}

func durationEnv(key, fallback string) (time.Duration, error) {
	raw := getEnv(key, fallback)
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a duration (use 15m, 720h)", key, raw)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive", key)
	}
	return d, nil
}

func splitList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := parts[:0]
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
