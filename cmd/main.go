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
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/membership"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/middleware"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/organization"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/role"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/routes"
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

	authRepo := auth.NewRepository(dbPool)
	authService := auth.NewService(authRepo, auditService, cfg, dbPool)
	authHandler := auth.NewHandler(authService, cfg)

	authzRepo := authz.NewRepository(dbPool)
	authzService := authz.NewService(authzRepo)
	authzHandler := authz.NewHandler(authzService)

	orgRepo := organization.NewRepository(dbPool)
	orgService := organization.NewService(orgRepo, dbPool)
	orgHandler := organization.NewHandler(orgService)

	membershipRepo := membership.NewRepository(dbPool)
	membershipService := membership.NewService(membershipRepo, dbPool)
	membershipHandler := membership.NewHandler(membershipService)

	roleRepo := role.NewRepository(dbPool)
	roleService := role.NewService(roleRepo)
	roleHandler := role.NewHandler(roleService)

	auditHandler := audit.NewHandler(auditRepo)

	// Rate limiters - one instance per key strategy, reused across every
	// route that shares it
	authIPLimiter := middleware.NewRateLimiter(5, 10)
	orgRateLimiter := middleware.NewRateLimiter(5, 10)

	// Routing
	rootMux := http.NewServeMux()
	routes.RegisterHealthRoutes(rootMux, healthHandler)

	apiMux := http.NewServeMux()
	routes.RegisterAPIRoutes(apiMux, routes.Dependencies{
		HealthHandler:     healthHandler,
		AuthHandler:       authHandler,
		AuthRepo:          authRepo,
		AuthzRepo:         authzRepo,
		AuthzHandler:      authzHandler,
		AuditHandler:      auditHandler,
		OrgHandler:        orgHandler,
		MembershipHandler: membershipHandler,
		RoleHandler:       roleHandler,
		AuthIPLimiter:     authIPLimiter,
		OrgRateLimiter:    orgRateLimiter,
	})

	apiStack := middleware.Recovery(
		middleware.RequestLogger(
			middleware.SecurityHeaders(
				middleware.CORS(middleware.CORSConfig{
					AllowedOrigins: cfg.CORSAllowedOrigins,
				})(apiMux),
			),
		),
	)
	rootMux.Handle("/v1/", http.StripPrefix("/v1", apiStack))

	// Server
	server := &http.Server{
		Addr:    ":" + cfg.AppPort,
		Handler: rootMux,
	}

	// Start Server
	serverErr := make(chan error, 1)
	go func() {
		logger.Info("Server is running...")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("Server failed to shutdown")
		os.Exit(1)
	}
	logger.Info("Server stopped")

	dbPool.Close()
	logger.Info("Database closed")
	logger.Info("Application shutdown completed")
	logger.Info("Application stopped")
}
