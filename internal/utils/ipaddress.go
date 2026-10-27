package utils

import (
	"net"
	"net/http"
	"strings"
)

// ClientIP prefers X-Forwarded-For, which is only trustworthy when the
// proxy overwrites it. Rate limiting and audit IPs depend on that.
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
