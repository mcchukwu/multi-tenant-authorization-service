package config

import (
	"strings"
	"testing"
)

func setValidEnv(t *testing.T) {
	t.Helper()
	t.Setenv("APP_NAME", "mtas")
	t.Setenv("APP_PORT", "8080")
	t.Setenv("APP_ENV", "development")
	t.Setenv("DATABASE_URL", "postgres://mtas:mtas@localhost:5432/mtas")
	t.Setenv("ACCESS_TOKEN_TTL", "15m")
	t.Setenv("REFRESH_TOKEN_TTL", "720h")
	t.Setenv("CORS_ALLOWED_ORIGINS", "http://localhost:5173, https://app.example.com")
}

func TestLoad(t *testing.T) {
	setValidEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := cfg.AccessTokenTTL.String(), "15m0s"; got != want {
		t.Fatalf("AccessTokenTTL = %s, want %s", got, want)
	}
	if got, want := len(cfg.CORSAllowedOrigins), 2; got != want {
		t.Fatalf("CORSAllowedOrigins = %v, want %d entries", cfg.CORSAllowedOrigins, want)
	}
}

func TestLoadRejectsBadDuration(t *testing.T) {
	setValidEnv(t)
	t.Setenv("REFRESH_TOKEN_TTL", "30d")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "REFRESH_TOKEN_TTL") {
		t.Fatalf("expected an error naming REFRESH_TOKEN_TTL, got %v", err)
	}
}

func TestLoadRejectsEmptyCORS(t *testing.T) {
	setValidEnv(t)
	t.Setenv("CORS_ALLOWED_ORIGINS", " ")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "CORS_ALLOWED_ORIGINS") {
		t.Fatalf("expected an error naming CORS_ALLOWED_ORIGINS, got %v", err)
	}
}

func TestLoadRejectsMissingDatabaseURL(t *testing.T) {
	setValidEnv(t)
	t.Setenv("DATABASE_URL", "")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "DATABASE_URL") {
		t.Fatalf("expected an error naming DATABASE_URL, got %v", err)
	}
}
