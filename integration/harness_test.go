// Package integration_test verifies the MTAS HTTP API end-to-end against a
// real PostgreSQL server running in Docker, through the EXACT same handler
// + middleware stack that cmd/main.go wires together at startup.
//
// Design decisions, and why:
//
//   - No mocking. The point of this tier is to prove the real SQL, the real
//     middleware chain, and the real route table agree with each other.
//     Repositories get a real *pgxpool.Pool; httptest.Server serves real
//     HTTP through Recovery -> RequestLogger -> SecurityHeaders -> CORS ->
//     Authn/Authz/rate-limiters -> handlers.
//
//   - One container per test binary run (TestMain), shared by all tests.
//     Each test creates its own users/orgs with unique identifiers, so tests
//     are data-isolated despite the shared database. Tests run serially:
//     the rate limiter is process-global state and parallel tests would
//     leak tokens across each other.
//
//   - Rate-limit isolation via X-Forwarded-For. ClientIP() (utils) prefers
//     XFF over RemoteAddr, and the auth routes' limiter is keyed on that IP.
//     Every test user gets a unique spoofed XFF address, which both isolates
//     tests from each other AND makes the rate-limit test deterministic.
//
//   - Manual cookie handling. Auth cookies are Secure+SameSite, and Go's
//     http.Client cookie jar will not store or send Secure cookies over
//     plain-HTTP httptest servers. We therefore track cookies ourselves,
//     honoring each cookie's Path just like a browser would.
//
//   - Migrations are applied with the SIMPLE query protocol: pgx's default
//     extended protocol rejects multi-statement query strings, and the
//     migration files each contain many statements (DDL, triggers, seeds).
package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

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

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Global harness state (TestMain)
// ---------------------------------------------------------------------------

var (
	server      *httptest.Server
	pool        *pgxpool.Pool
	appConfig   *config.Config
	ipSequencer atomic.Uint64
)

// testPassword satisfies RegisterRequest's min=8 validation for every user
// created by the harness. Deliberately a shared constant — password strength
// is not what these tests are about.
const testPassword = "Sup3rSecret!123"

func TestMain(m *testing.M) {
	code := run(m)
	if pool != nil {
		pool.Close()
	}
	os.Exit(code)
}

func run(m *testing.M) int {
	if err := requireDocker(); err != nil {
		// The Makefile `test` target runs `go test ./...`; on a machine
		// without Docker this tier cannot run. Skipping with an explicit
		// message is friendlier (and keeps `go test ./...` green) than
		// hard-failing.
		fmt.Fprintf(os.Stderr, "SKIP integration tests: Docker unavailable (%v)\n", err)
		return 0
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dsn, cleanup, err := startPostgres(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration tests: failed to start Postgres container: %v\n", err)
		return 1
	}
	defer cleanup()

	if err := applyMigrations(ctx, dsn); err != nil {
		fmt.Fprintf(os.Stderr, "integration tests: failed to apply migrations: %v\n", err)
		return 1
	}

	// The real production connect function: connection pooling config,
	// ping, everything the app itself does.
	pool, err = db.Connect(dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration tests: failed to connect: %v\n", err)
		return 1
	}

	appConfig = &config.Config{
		AppName:            "mtas-test",
		AppPort:            "0",
		AppEnv:             "development",
		DBURL:              dsn,
		AccessTokenTTL:     15 * time.Minute,
		RefreshTokenTTL:    30 * 24 * time.Hour,
		CORSAllowedOrigins: []string{"http://localhost:5173"},
	}

	server = buildServer(pool, appConfig)
	defer server.Close()

	return m.Run()
}

// requireDocker fails fast if the docker CLI cannot talk to a daemon.
func requireDocker() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		return fmt.Errorf("docker daemon unreachable: %w", err)
	}
	return nil
}

// startPostgres runs a throwaway postgres:18 container with a random host
// port (no collision risk), waits until it accepts connections, and returns
// its DSN plus a cleanup func. The container name is unique per run so a
// leaked container from a killed test process can't collide with the next
// run.
func startPostgres(ctx context.Context) (string, func(), error) {
	name := "mtas-it-" + uuid.NewString()[:8]

	run := exec.CommandContext(ctx, "docker", "run", "-d", "--rm", "--name", name,
		"-e", "POSTGRES_USER=mtas",
		"-e", "POSTGRES_PASSWORD=mtas",
		"-e", "POSTGRES_DB=mtas",
		"-p", "127.0.0.1::5432", // host port assigned by docker, shown by `docker port`
		"postgres:18",
	)
	if out, err := run.CombinedOutput(); err != nil {
		return "", nil, fmt.Errorf("docker run: %v: %s", err, out)
	}

	cleanup := func() {
		ctx2, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx2, "docker", "rm", "-f", name).Run() // best-effort
	}

	portOut, err := exec.CommandContext(ctx, "docker", "port", name, "5432/tcp").Output()
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("docker port: %v", err)
	}
	hostPort := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(portOut)), "127.0.0.1:"))
	if hostPort == "" {
		cleanup()
		return "", nil, fmt.Errorf("docker port: unexpected output %q", portOut)
	}

	dsn := fmt.Sprintf("postgres://mtas:mtas@127.0.0.1:%s/mtas?sslmode=disable", hostPort)

	if err := waitForDBReady(ctx, dsn); err != nil {
		cleanup()
		return "", nil, err
	}
	return dsn, cleanup, nil
}

// waitForDBReady polls with a real pgx connection + Ping until Postgres is
// accepting queries. Polling the actual thing we need beats parsing log
// output for "ready" lines, and one failed connect attempt (auth still
// initializing) is not a reason to give up.
func waitForDBReady(ctx context.Context, dsn string) error {
	const attempts = 60
	for i := 0; i < attempts; i++ {
		conn, err := pgx.Connect(ctx, dsn)
		if err == nil {
			pingErr := conn.Ping(ctx)
			_ = conn.Close(ctx)
			if pingErr == nil {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("postgres did not become ready within %d attempts", attempts)
}

// migrations list in application order. Order matters: 000002/000003 seed
// the global catalog, 000004 installs the org-provisioning trigger that
// every org created afterward depends on.
var migrations = []string{
	"000001_init_schema.up.sql",
	"000002_seed_permissions.up.sql",
	"000003_seed_template_roles.up.sql",
	"000004_seed_org_defaults_function.up.sql",
}

// applyMigrations runs every migration file verbatim. Each file contains
// many statements, so the connection must use the SIMPLE query protocol —
// pgx's default extended protocol rejects multi-statement strings.
func applyMigrations(ctx context.Context, dsn string) error {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return err
	}
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	root, err := repoRoot()
	if err != nil {
		return err
	}

	for _, name := range migrations {
		path := filepath.Join(root, "migrations", name)
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		if _, err := conn.Exec(ctx, string(content)); err != nil {
			return fmt.Errorf("apply %s: %w", name, err)
		}
	}
	return nil
}

// repoRoot walks up from the test package's working directory to the
// directory containing go.mod — robust whether tests are run from the repo
// root (`go test ./...`) or from inside the package (`go test ./integration`).
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found above %s", dir)
		}
		dir = parent
	}
}

// buildServer mirrors cmd/main.go's wiring line for line: same dependency
// graph, same middleware nesting, same rate-limiter parameters (5 rps,
// burst 10), same route registration under /v1. If this diverges from
// production wiring, the tests are no longer testing the real system.
func buildServer(pool *pgxpool.Pool, cfg *config.Config) *httptest.Server {
	healthHandler := health.NewHandler(pool)

	auditRepo := audit.NewRepository(pool)
	auditService := audit.NewService(auditRepo)

	authRepo := auth.NewRepository(pool)
	authService := auth.NewService(authRepo, auditService, cfg, pool)
	authHandler := auth.NewHandler(authService, cfg)

	authzRepo := authz.NewRepository(pool)
	authzService := authz.NewService(authzRepo)
	authzHandler := authz.NewHandler(authzService)

	orgRepo := organization.NewRepository(pool)
	orgService := organization.NewService(orgRepo, pool)
	orgHandler := organization.NewHandler(orgService)

	membershipRepo := membership.NewRepository(pool)
	membershipService := membership.NewService(membershipRepo, pool)
	membershipHandler := membership.NewHandler(membershipService)

	roleRepo := role.NewRepository(pool)
	roleService := role.NewService(roleRepo)
	roleHandler := role.NewHandler(roleService)

	auditHandler := audit.NewHandler(auditRepo)

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
				})(apiMux),
			),
		),
	)
	rootMux.Handle("/v1/", http.StripPrefix("/v1", apiStack))

	return httptest.NewServer(rootMux)
}

// ---------------------------------------------------------------------------
// HTTP client helper
// ---------------------------------------------------------------------------

// apiClient is a thin cookie-aware HTTP client. Each test user gets its own
// client so cookie state is never shared; each client has its own spoofed
// X-Forwarded-For IP so the IP-keyed auth rate limiter treats it as an
// isolated visitor. The client also carries the user's current access token
// and attaches it as `Authorization: Bearer <token>` automatically — so a
// client created by registerUser/loginOn is authenticated everywhere, while
// a bare newClient (no token) is unauthenticated by construction.
type apiClient struct {
	base    string
	ip      string
	token   string // access token; "" = unauthenticated
	hc      *http.Client
	cookies map[string]*http.Cookie
}

func newClient(t *testing.T) *apiClient {
	t.Helper()
	n := ipSequencer.Add(1)
	return &apiClient{
		base:    server.URL,
		ip:      fmt.Sprintf("10.255.%d.%d", (n>>8)&0xFF, n&0xFF),
		hc:      &http.Client{Timeout: 15 * time.Second},
		cookies: map[string]*http.Cookie{},
	}
}

// do performs one request. It attaches the client's X-Forwarded-For, sends
// every stored cookie whose Path matches the request path (browser
// semantics), and absorbs any Set-Cookie from the response.
func (c *apiClient) do(t *testing.T, method, path string, body any, headers http.Header) (int, http.Header, []byte) {
	t.Helper()

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		require.NoError(t, err, "marshal request body")
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, c.base+path, reader)
	require.NoError(t, err, "build request")
	req.Header.Set("X-Forwarded-For", c.ip)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Extra headers use Set, so an explicitly passed header (e.g. a
	// deliberately different bearer token) overrides the client's own.
	for key, values := range headers {
		for _, v := range values {
			req.Header.Set(key, v)
		}
	}
	for _, cookie := range c.cookies {
		if strings.HasPrefix(path, cookie.Path) {
			req.AddCookie(cookie)
		}
	}

	resp, err := c.hc.Do(req)
	require.NoError(t, err, "%s %s", method, path)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read %s %s response", method, path)

	for _, cookie := range resp.Cookies() {
		c.cookies[cookie.Name] = cookie
	}

	return resp.StatusCode, resp.Header, respBody
}

// csrfCookie returns the current csrf_token cookie value, or "" if absent.
func (c *apiClient) csrfCookie() string {
	if ck, ok := c.cookies["csrf_token"]; ok {
		return ck.Value
	}
	return ""
}

// refreshCookie returns the current refresh_token cookie value, or "".
func (c *apiClient) refreshCookie() string {
	if ck, ok := c.cookies["refresh_token"]; ok {
		return ck.Value
	}
	return ""
}

// refresh POSTs /v1/auth/refresh with the client's cookies and the given
// X-CSRF-Token header value (the double-submit pattern). Callers pass the
// value explicitly so tests can replay OLD tokens deliberately.
func (c *apiClient) refresh(t *testing.T, csrfHeader string) (int, []byte) {
	t.Helper()
	headers := http.Header{"X-CSRF-Token": []string{csrfHeader}}
	status, _, body := c.do(t, http.MethodPost, "/v1/auth/refresh", nil, headers)
	return status, body
}

// refreshWithCookies POSTs /v1/auth/refresh presenting EXPLICIT cookie
// values (refresh + CSRF) plus the CSRF header. This is how tests replay a
// stale token pair: the client's live cookie jar would otherwise silently
// upgrade to the newest pair, and the CSRF check (which runs BEFORE token
// validation) would reject the replay before the reuse-detection logic ever
// saw the token.
func (c *apiClient) refreshWithCookies(t *testing.T, refreshValue, csrfValue, csrfHeader string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, c.base+"/v1/auth/refresh", nil)
	require.NoError(t, err)
	req.Header.Set("X-Forwarded-For", c.ip)
	req.Header.Set("X-CSRF-Token", csrfHeader)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshValue, Path: "/v1/auth"})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfValue, Path: "/v1/auth"})

	resp, err := c.hc.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Absorb any Set-Cookie so the client stays coherent for later asserts.
	for _, cookie := range resp.Cookies() {
		c.cookies[cookie.Name] = cookie
	}
	return resp.StatusCode, respBody
}

// ---------------------------------------------------------------------------
// Response envelope helpers
// ---------------------------------------------------------------------------

// envelope matches response.Success: {success, message, data}.
type envelope struct {
	Success bool            `json:"success"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// errEnvelope matches response.Error / ValidationError: {success, error{code, message, fields}}.
type errEnvelope struct {
	Success bool `json:"success"`
	Error   struct {
		Code    string            `json:"code"`
		Message string            `json:"message"`
		Fields  map[string]string `json:"fields"`
	} `json:"error"`
}

// expectStatus performs a request and requires the given status, returning
// the raw body for further decoding. Used by both success and error paths.
func expectStatus(t *testing.T, c *apiClient, method, path string, body any, wantStatus int, headers http.Header) []byte {
	t.Helper()
	status, _, respBody := c.do(t, method, path, body, headers)
	require.Equalf(t, wantStatus, status,
		"%s %s: expected status %d, got %d (body: %s)", method, path, wantStatus, status, respBody)
	return respBody
}

// expectError performs a request, requires wantStatus, and returns the error
// code string from the JSON envelope (e.g. "forbidden", "last_owner").
// Optional extra headers (e.g. an Authorization bearer) are appended to the
// request.
func expectError(t *testing.T, c *apiClient, method, path string, body any, wantStatus int, extraHeaders ...http.Header) string {
	t.Helper()
	headers := http.Header{}
	for _, h := range extraHeaders {
		for k, vs := range h {
			for _, v := range vs {
				headers.Add(k, v)
			}
		}
	}
	respBody := expectStatus(t, c, method, path, body, wantStatus, headers)

	var env errEnvelope
	require.NoError(t, json.Unmarshal(respBody, &env), "decode error body %s", respBody)
	require.False(t, env.Success, "error response should carry success=false: %s", respBody)
	require.NotEmpty(t, env.Error.Code, "error response should carry an error code: %s", respBody)
	return env.Error.Code
}

// decodeData performs a request expecting a 2xx success envelope and returns
// the decoded Data payload as a generic map.
func decodeData(t *testing.T, c *apiClient, method, path string, wantStatus int, extraHeaders ...http.Header) map[string]any {
	t.Helper()
	headers := http.Header{}
	for _, h := range extraHeaders {
		for k, vs := range h {
			for _, v := range vs {
				headers.Add(k, v)
			}
		}
	}
	respBody := expectStatus(t, c, method, path, nil, wantStatus, headers)

	var env envelope
	require.NoError(t, json.Unmarshal(respBody, &env), "decode success body %s", respBody)
	require.True(t, env.Success, "response should carry success=true: %s", respBody)

	var data map[string]any
	require.NoError(t, json.Unmarshal(env.Data, &data), "decode data %s", env.Data)
	return data
}

// ---------------------------------------------------------------------------
// Domain fixtures
// ---------------------------------------------------------------------------

// testUser is a registered user plus everything derived from that: their own
// cookie-authenticated client, access token, and the personal org that
// registration automatically provisions.
type testUser struct {
	client        *apiClient
	email         string
	password      string
	accessToken   string
	userID        string
	personalOrgID string
}

// registerUser runs the real register endpoint and captures the tokens,
// cookies, user id, and personal org id. Emails are unique per call (the
// users table has a UNIQUE constraint; tests share one database).
func registerUser(t *testing.T, label string) *testUser {
	t.Helper()
	c := newClient(t)
	email := fmt.Sprintf("%s-%s@example.com", label, uuid.NewString()[:8])

	respBody := expectStatus(t, c, http.MethodPost, "/v1/auth/register",
		map[string]any{
			"email":      email,
			"password":   testPassword,
			"first_name": label,
			"last_name":  "Test",
		},
		http.StatusCreated, nil,
	)

	var env envelope
	require.NoError(t, json.Unmarshal(respBody, &env))
	var data struct {
		AccessToken  string `json:"access_token"`
		User         struct {
			ID string `json:"id"`
		} `json:"user"`
		Organization struct {
			ID string `json:"id"`
		} `json:"organization"`
	}
	require.NoError(t, json.Unmarshal(env.Data, &data))
	require.NotEmpty(t, data.AccessToken, "register must return an access token")
	require.NotEmpty(t, c.refreshCookie(), "register must set a refresh_token cookie")
	require.NotEmpty(t, c.csrfCookie(), "register must set a csrf_token cookie")

	c.token = data.AccessToken // from here on this client authenticates as this user

	return &testUser{
		client:        c,
		email:         email,
		password:      testPassword,
		accessToken:   data.AccessToken,
		userID:        data.User.ID,
		personalOrgID: data.Organization.ID,
	}
}

// bearer returns a header set that authenticates this user as
// `Authorization: Bearer <token>`.
func (u *testUser) bearer() http.Header {
	return http.Header{"Authorization": []string{"Bearer " + u.accessToken}}
}

// login performs POST /v1/auth/login as this user on their OWN client
// (same device) and updates the stored access token. For a second device,
// use loginOn.
func (u *testUser) login(t *testing.T) {
	t.Helper()
	u.accessToken = loginOn(t, u.client, u.email, u.password)
}

// loginOn logs in with a given client (a different "device" / session).
func loginOn(t *testing.T, c *apiClient, email, password string) string {
	t.Helper()
	respBody := expectStatus(t, c, http.MethodPost, "/v1/auth/login",
		map[string]any{"identifier": email, "password": password},
		http.StatusOK, nil,
	)
	var env envelope
	require.NoError(t, json.Unmarshal(respBody, &env))
	var data struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(env.Data, &data))
	require.NotEmpty(t, data.AccessToken, "login must return an access token")
	require.NotEmpty(t, c.refreshCookie(), "login must set a refresh_token cookie")
	c.token = data.AccessToken // this client is now that session
	return data.AccessToken
}

// orgFixture is the canonical seeded organization: one business org owned by
// Owner with one member of each of the four system role kinds, reached
// through the real invite+accept flow (which doubles as coverage of that
// flow itself).
type orgFixture struct {
	OrgID  string
	Owner  *testUser
	Admin  *testUser
	Member *testUser
	Viewer *testUser
	Roles  map[string]string // role kind -> role ID, e.g. Roles["owner"]
}

// seedOrg registers owner/admin/member/viewer, has the owner create a
// business org, then invites each staff member via the invite endpoint and
// has them accept — the same journey a real team goes through.
func seedOrg(t *testing.T, label string) *orgFixture {
	t.Helper()

	owner := registerUser(t, label+"-owner")
	admin := registerUser(t, label+"-admin")
	member := registerUser(t, label+"-member")
	viewer := registerUser(t, label+"-viewer")

	// Owner creates a business org. Registration already created their
	// personal org; this is a separate tenant.
	respBody := expectStatus(t, owner.client, http.MethodPost, "/v1/orgs",
		map[string]any{"name": label + "'s Company"}, http.StatusCreated, owner.bearer())
	var env envelope
	require.NoError(t, json.Unmarshal(respBody, &env))
	var created struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	require.NoError(t, json.Unmarshal(env.Data, &created))
	require.Equal(t, "business", created.Type, "orgs created via POST /orgs are always business type")

	roles := orgRolesByKind(t, owner, created.ID)
	require.Contains(t, roles, "owner", "every org must have an owner role")
	require.Contains(t, roles, "admin", "every org must have an admin role")
	require.Contains(t, roles, "member", "every org must have a member role")
	require.Contains(t, roles, "viewer", "every org must have a viewer role")

	inviteAndAccept(t, owner, admin, created.ID, roles["admin"])
	inviteAndAccept(t, owner, member, created.ID, roles["member"])
	inviteAndAccept(t, owner, viewer, created.ID, roles["viewer"])

	return &orgFixture{
		OrgID:  created.ID,
		Owner:  owner,
		Admin:  admin,
		Member: member,
		Viewer: viewer,
		Roles:  roles,
	}
}

// orgRolesByKind lists the org's roles and indexes them by kind (stable
// identifier — never by name, since names are editable).
func orgRolesByKind(t *testing.T, actor *testUser, orgID string) map[string]string {
	t.Helper()
	respBody := expectStatus(t, actor.client, http.MethodGet,
		"/v1/orgs/"+orgID+"/roles", nil, http.StatusOK, actor.bearer())
	var env envelope
	require.NoError(t, json.Unmarshal(respBody, &env))
	var roles []struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	}
	require.NoError(t, json.Unmarshal(env.Data, &roles))

	byKind := make(map[string]string, len(roles))
	for _, r := range roles {
		byKind[r.Kind] = r.ID
	}
	return byKind
}

// inviteAndAccept runs the full invite journey: inviter creates a link
// invitation for a role, invitee accepts it with their own session.
func inviteAndAccept(t *testing.T, inviter, invitee *testUser, orgID, roleID string) {
	t.Helper()
	respBody := expectStatus(t, inviter.client, http.MethodPost,
		"/v1/orgs/"+orgID+"/members/invite",
		map[string]any{"role_id": roleID}, http.StatusCreated, inviter.bearer())

	var env envelope
	require.NoError(t, json.Unmarshal(respBody, &env))
	var data struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(env.Data, &data))
	require.NotEmpty(t, data.Token, "invite must return a raw invitation token")

	// Accept route is NOT org-scoped and requires only authentication.
	acceptBody := expectStatus(t, invitee.client, http.MethodPost,
		"/v1/auth/invitations/"+data.Token+"/accept", nil, http.StatusOK, invitee.bearer())
	var acceptEnv envelope
	require.NoError(t, json.Unmarshal(acceptBody, &acceptEnv))
	var accepted struct {
		OrganizationID string `json:"organization_id"`
	}
	require.NoError(t, json.Unmarshal(acceptEnv.Data, &accepted))
	require.Equal(t, orgID, accepted.OrganizationID, "invitation must resolve to the inviting org")
}
