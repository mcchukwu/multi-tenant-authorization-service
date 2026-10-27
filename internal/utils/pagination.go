package utils

import (
	"net/http"
	"strconv"
)

// ParsePagination reads ?limit=&offset= with sane defaults and bounds.
// Used by both audit-log and authz-decision listing, so the two don't
// each grow their own slightly-different parsing.
func ParsePagination(r *http.Request) (limit, offset int) {
	limit = 50
	offset = 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}
