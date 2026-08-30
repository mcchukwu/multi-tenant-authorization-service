package routes

import (
	"net/http"

	"github.com/mcchukwu/multi-tenant-authorization-service/internal/auth"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/authz"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/health"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/membership"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/middleware"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/organization"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/utils"
)

// Dependencies holds everything the route table needs to wire handlers to
// middleware. main.go builds this once at startup; this package only
// reads from it.
type Dependencies struct {
	HealthHandler *health.Handler

	AuthHandler       *auth.Handler
	AuthRepo          *auth.Repository
	AuthzRepo         *authz.Repository
	OrgHandler        *organization.Handler
	MembershipHandler *membership.Handler

	AuthIPLimiter  *middleware.RateLimiter
	OrgRateLimiter *middleware.RateLimiter
}

// RegisterHealthRoutes registers on its own mux
func RegisterHealthRoutes(mux *http.ServeMux, h *health.Handler) {
	mux.HandleFunc("GET /health", h.Health)
	mux.HandleFunc("GET /health/live", h.Live)
	mux.HandleFunc("GET /health/ready", h.Ready)
}

// RegisterAPIRoutes registers every versioned route
func RegisterAPIRoutes(mux *http.ServeMux, d Dependencies) {
	ipKey := func(r *http.Request) string { return utils.ClientIP(r) }
	orgKey := func(r *http.Request) string { return r.PathValue("org_id") }

	// Auth: pre-tenant, IP-keyed rate limiting only
	mux.Handle("POST /auth/login",
		d.AuthIPLimiter.Middleware(ipKey)(
			http.HandlerFunc(d.AuthHandler.Login),
		),
	)
	mux.Handle("POST /auth/register",
		d.AuthIPLimiter.Middleware(ipKey)(
			http.HandlerFunc(d.AuthHandler.Register),
		),
	)
	mux.Handle("POST /auth/refresh",
		d.AuthIPLimiter.Middleware(ipKey)(
			http.HandlerFunc(d.AuthHandler.Refresh),
		),
	)

	// Session/device management, Authn only, no {org_id}
	mux.Handle("POST /auth/logout",
		middleware.Authn(d.AuthRepo)(
			http.HandlerFunc(d.AuthHandler.Logout),
		),
	)
	mux.Handle("POST /auth/logout-all",
		middleware.Authn(d.AuthRepo)(
			http.HandlerFunc(d.AuthHandler.LogoutAll),
		),
	)
	mux.Handle("GET /auth/sessions",
		middleware.Authn(d.AuthRepo)(
			http.HandlerFunc(d.AuthHandler.ListSessions),
		),
	)

	// Invitation accept: no {org_id} exists yet at this point
	mux.Handle("POST /auth/invitations/{token}/accept",
		d.AuthIPLimiter.Middleware(ipKey)(
			middleware.Authn(d.AuthRepo)(
				http.HandlerFunc(d.MembershipHandler.Accept),
			),
		),
	)

	// Organizations: creation is Authn-only, everything else is
	// Authn + Authz + org-keyed rate limiting
	mux.Handle("POST /orgs",
		middleware.Authn(d.AuthRepo)(
			http.HandlerFunc(d.OrgHandler.Create),
		),
	)

	mux.Handle("GET /orgs/{org_id}",
		d.OrgRateLimiter.Middleware(orgKey)(
			middleware.Authn(d.AuthRepo)(
				middleware.Authz(d.AuthzRepo, "org.view")(
					http.HandlerFunc(d.OrgHandler.Get),
				),
			),
		),
	)
	mux.Handle("PATCH /orgs/{org_id}",
		d.OrgRateLimiter.Middleware(orgKey)(
			middleware.Authn(d.AuthRepo)(
				middleware.Authz(d.AuthzRepo, "org.update")(
					http.HandlerFunc(d.OrgHandler.Update),
				),
			),
		),
	)
	mux.Handle("DELETE /orgs/{org_id}",
		d.OrgRateLimiter.Middleware(orgKey)(
			middleware.Authn(d.AuthRepo)(
				middleware.Authz(d.AuthzRepo, "org.delete")(
					http.HandlerFunc(d.OrgHandler.Delete),
				),
			),
		),
	)

	// Members: all org-scoped, all org-keyed rate limiting
	mux.Handle("GET /orgs/{org_id}/members",
		d.OrgRateLimiter.Middleware(orgKey)(
			middleware.Authn(d.AuthRepo)(
				middleware.Authz(d.AuthzRepo, "member.view")(
					http.HandlerFunc(d.MembershipHandler.List),
				),
			),
		),
	)
	mux.Handle("POST /orgs/{org_id}/members/invite",
		d.OrgRateLimiter.Middleware(orgKey)(
			middleware.Authn(d.AuthRepo)(
				middleware.Authz(d.AuthzRepo, "member.invite")(
					http.HandlerFunc(d.MembershipHandler.Invite),
				),
			),
		),
	)
	mux.Handle("DELETE /orgs/{org_id}/members/{user_id}",
		d.OrgRateLimiter.Middleware(orgKey)(
			middleware.Authn(d.AuthRepo)(
				middleware.Authz(d.AuthzRepo, "member.remove")(
					http.HandlerFunc(d.MembershipHandler.Remove),
				),
			),
		),
	)
	mux.Handle("PATCH /orgs/{org_id}/members/{user_id}/role",
		d.OrgRateLimiter.Middleware(orgKey)(
			middleware.Authn(d.AuthRepo)(
				middleware.Authz(d.AuthzRepo, "member.assign_role")(
					http.HandlerFunc(d.MembershipHandler.AssignRole),
				),
			),
		),
	)
}
