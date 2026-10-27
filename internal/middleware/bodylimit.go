package middleware

import "net/http"

// MaxBodyBytes is generous for JSON, small enough that a request body
// cannot be used to exhaust memory.
const MaxBodyBytes = 64 << 10

func BodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}
