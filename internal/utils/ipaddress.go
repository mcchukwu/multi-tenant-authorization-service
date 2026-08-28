package utils

import (
	"net"
	"net/http"
	"strings"
)

// clientIP prefers X-Forwarded-For (set by a reverse proxy/load balancer)
// over RemoteAddr, since RemoteAddr is the proxy's own address once you're
// behind one. XFF is itself spoofable by the client unless your proxy is
// configured to overwrite rather than append to it — confirm that's true
// of your deployment before relying on this for anything security-critical
// like the per-tenant rate limiting you've got planned.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

