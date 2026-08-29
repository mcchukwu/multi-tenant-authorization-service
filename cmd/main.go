package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mcchukwu/multi-tenant-authorization-service/internal/audit"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/auth"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/authz"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/health"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/middleware"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/organization"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/utils"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/config"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/db"
	"github.com/mcchukwu/multi-tenant-authorization-service/pkg/logger"
)

func main() {
	// Configuration
	cfg := config.Load()
	if err := config.Validate(cfg); err != nil {
		logger.Error("Invalid configuration")
		os.Exit(1)
	}

	// Infrastructure
	dbPool, err := db.Connect(cfg.DBURL)
	if err != nil {
		logger.Error("Failed to connect to database")
		os.Exit(1)
	}
	logger.Info("Connected to database")

	// Dependencies
	healthHandler := health.NewHandler(dbPool)

	auditRepo := audit.NewRepository(dbPool)
	auditService := audit.NewService(auditRepo)

	authnRepo := auth.NewRepository(dbPool)
	authnService := auth.NewService(authnRepo, auditService, cfg, dbPool)
	authnHandler := auth.NewHandler(authnService, cfg)

	authzRepo := authz.NewRepository(dbPool)

	orgRepo := organization.NewRepository(dbPool)
	orgService := organization.NewService(orgRepo, dbPool)
	orgHandler := organization.NewHandler(orgService)

	// Middlewares
	authIPLimiter := middleware.NewRateLimiter(5, 10)
	orgIPLimiter := middleware.NewRateLimiter(5, 10)

	// Routing
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", healthHandler.Health)
	mux.HandleFunc("GET /health/live", healthHandler.Live)
	mux.HandleFunc("GET /health/ready", healthHandler.Ready)

	mux.Handle("POST /auth/login",
		authIPLimiter.Middleware(func(r *http.Request) string { return utils.ClientIP(r) })(
			http.HandlerFunc(authnHandler.Login),
		),
	)
	mux.Handle("POST /auth/register",
		authIPLimiter.Middleware(func(r *http.Request) string { return utils.ClientIP(r) })(
			http.HandlerFunc(authnHandler.Register),
		),
	)
	mux.Handle("POST /auth/refresh",
		authIPLimiter.Middleware(func(r *http.Request) string { return utils.ClientIP(r) })(
			http.HandlerFunc(authnHandler.Refresh),
		),
	)

	// Protected routes
	mux.Handle("POST /orgs",
		middleware.Authn(authnRepo)(
			orgIPLimiter.Middleware(func(r *http.Request) string { return utils.ClientIP(r) })(
				http.HandlerFunc(orgHandler.Create),
			),
		),
	)

	// Organization routes
	mux.Handle("GET /orgs/{org_id}",
		middleware.Authn(authnRepo)(
			middleware.Authz(authzRepo, "org.view")(
				orgIPLimiter.Middleware(func(r *http.Request) string { return utils.ClientIP(r) })(
					http.HandlerFunc(orgHandler.Get),
				),
			),
		),
	)
	mux.Handle("PATCH /orgs/{org_id}",
		middleware.Authn(authnRepo)(
			middleware.Authz(authzRepo, "org.update")(
				orgIPLimiter.Middleware(func(r *http.Request) string { return utils.ClientIP(r) })(
					http.HandlerFunc(orgHandler.Update),
				),
			),
		),
	)
	mux.Handle("DELETE /orgs/{org_id}",
		middleware.Authn(authnRepo)(
			middleware.Authz(authzRepo, "org.delete")(
				orgIPLimiter.Middleware(func(r *http.Request) string { return utils.ClientIP(r) })(
					http.HandlerFunc(orgHandler.Delete),
				),
			),
		),
	)

	// Handler stack
	handlerStack := middleware.Recovery(
		middleware.RequestLogger(
			middleware.SecurityHeaders(
				middleware.CORS(middleware.CORSConfig{
					AllowedOrigins: cfg.CORSAllowedOrigins,
				})(
					mux,
				),
			),
		),
	)

	v1 := http.NewServeMux()
	v1.Handle("/v1/", http.StripPrefix("/v1", handlerStack))

	// Server
	server := &http.Server{
		Addr:    ":" + cfg.AppPort,
		Handler: v1,
	}

	// Start Server
	serverErr := make(chan error, 1)
	go func() {
		logger.Info("Server is running...")
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	healthHandler.SetReady(true)
	logger.Info("Application is ready")

	// Wait for shutdown signal
	shutdownSignal := make(chan os.Signal, 1)
	signal.Notify(shutdownSignal, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(shutdownSignal)

	select {
	case <-shutdownSignal:
		healthHandler.SetReady(false)
	case <-serverErr:
		logger.Error("Server failed to start")
		os.Exit(1)
	}

	// Start graceful shutdown
	logger.Info("Application shutdown started")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Stop accepting new HTTP requests and wait for active requests to finish
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("Server failed to shutdown")
		os.Exit(1)
	}
	logger.Info("Server stopped")

	// The HTTP server has finished, so nothing should still be using the database through HTTP handlers.
	dbPool.Close()
	logger.Info("Database closed")
	logger.Info("Application shutdown completed")
	logger.Info("Application stopped")
}
