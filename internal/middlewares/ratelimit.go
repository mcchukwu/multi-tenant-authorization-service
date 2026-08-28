package middleware

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/mcchukwu/multi-tenant-authorization-service/internal/response"
)

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter is deliberately generic over what a "key" means — a per-IP
// limiter for pre-authentication routes (login/register/refresh, where
// no tenant exists yet) and a per-org limiter for tenant-scoped routes
// (once step 3 exists) are the same struct with a different KeyFunc; the
// limiting mechanism itself doesn't know or care what the key represents.
type RateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rps      rate.Limit
	burst    int
}

func NewRateLimiter(requestsPerSecond rate.Limit, burst int) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rps:      requestsPerSecond,
		burst:    burst,
	}
	go rl.cleanupLoop()
	return rl
}

func (rl *RateLimiter) getLimiter(key string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[key]
	if !exists {
		limiter := rate.NewLimiter(rl.rps, rl.burst)
		rl.visitors[key] = &visitor{limiter: limiter, lastSeen: time.Now()}
		return limiter
	}
	v.lastSeen = time.Now()
	return v.limiter
}

// cleanupLoop evicts keys not seen recently, so the map doesn't grow
// unbounded as new IPs/orgs show up over the service's lifetime — without
// this, the rate limiter itself becomes a slow memory leak.
func (rl *RateLimiter) cleanupLoop() {
	for {
		time.Sleep(time.Minute)
		rl.mu.Lock()
		for key, v := range rl.visitors {
			if time.Since(v.lastSeen) > 3*time.Minute {
				delete(rl.visitors, key)
			}
		}
		rl.mu.Unlock()
	}
}

// KeyFunc extracts the rate-limit key from a request — e.g. IP address
// for anonymous auth routes, or org ID (from requestctx, set by Authz)
// for tenant-scoped routes.
type KeyFunc func(r *http.Request) string

func (rl *RateLimiter) Middleware(keyFunc KeyFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFunc(r)
			limiter := rl.getLimiter(key)

			// Exposes remaining quota so well-behaved clients can
			// self-throttle before hitting the wall — same principle as
			// the rate-limiting item in the production API checklist.
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(int(limiter.Tokens())))

			if !limiter.Allow() {
				w.Header().Set("Retry-After", "60")
				response.Error(w, http.StatusTooManyRequests, "rate_limited", "Too many requests, please try again later")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
