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
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/config"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/db"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/health"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/logger"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/membership"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/middleware"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/organization"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/role"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/routes"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "err", err)
		os.Exit(1)
	}

	dbPool, err := db.Connect(cfg.DBURL)
	if err != nil {
		logger.Error("database connection failed", "err", err)
		os.Exit(1)
	}
	logger.Info("Connected to database")

	healthHandler := health.NewHandler(dbPool)

	auditRepo := audit.NewRepository(dbPool)
	auditService := audit.NewService(auditRepo)

	authRepo := auth.NewRepository(dbPool)
	authService := auth.NewService(authRepo, auditService, cfg, dbPool)
	authHandler := auth.NewHandler(authService)

	authzRepo := authz.NewRepository(dbPool)
	authzHandler := authz.NewHandler(authzRepo)

	orgRepo := organization.NewRepository(dbPool)
	orgService := organization.NewService(orgRepo, dbPool)
	orgHandler := organization.NewHandler(orgService)

	membershipRepo := membership.NewRepository(dbPool)
	membershipService := membership.NewService(membershipRepo, dbPool)
	membershipHandler := membership.NewHandler(membershipService)

	roleRepo := role.NewRepository(dbPool)
	roleHandler := role.NewHandler(roleRepo)

	auditHandler := audit.NewHandler(auditRepo)

	// One limiter per key strategy, shared by every route that uses it.
	authIPLimiter := middleware.NewRateLimiter(5, 10)
	orgRateLimiter := middleware.NewRateLimiter(5, 10)

	rootMux := http.NewServeMux()
	routes.RegisterHealthRoutes(rootMux, healthHandler)

	apiMux := http.NewServeMux()
	routes.RegisterAPIRoutes(apiMux, routes.Dependencies{
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
				})(middleware.BodyLimit(apiMux)),
			),
		),
	)
	rootMux.Handle("/v1/", http.StripPrefix("/v1", apiStack))

	server := &http.Server{
		Addr:              ":" + cfg.AppPort,
		Handler:           rootMux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("Server is running...")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	healthHandler.SetReady(true)
	logger.Info("Application is ready")

	shutdownSignal := make(chan os.Signal, 1)
	signal.Notify(shutdownSignal, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(shutdownSignal)

	select {
	case <-shutdownSignal:
		healthHandler.SetReady(false)
	case err := <-serverErr:
		logger.Error("server failed", "err", err)
		os.Exit(1)
	}

	logger.Info("Application shutdown started")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("server shutdown failed", "err", err)
		os.Exit(1)
	}
	logger.Info("Server stopped")

	dbPool.Close()
	logger.Info("Database closed")
	logger.Info("Application shutdown completed")
	logger.Info("Application stopped")
}
