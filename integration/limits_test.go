package integration_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequestBodyLimit(t *testing.T) {
	c := newClient(t)

	// Passes validation shape, but the body is well over the 64 KiB cap.
	body := map[string]any{
		"email":      "large@example.com",
		"password":   strings.Repeat("a", 128<<10),
		"first_name": "Large",
	}

	status, _, respBody := c.do(t, http.MethodPost, "/v1/auth/register", body, nil)
	require.Equal(t, http.StatusBadRequest, status, "oversized body must be rejected: %s", respBody)
}
