package health

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/apperrors"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/response"
)

type Handler struct {
	db    *pgxpool.Pool
	ready atomic.Bool
}

func NewHandler(db *pgxpool.Pool) *Handler {
	return &Handler{
		db: db,
	}
}

func (h *Handler) SetReady(ready bool) {
	h.ready.Store(ready)
}

func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	response.Success(w, http.StatusOK, "service healthy", map[string]any{
		"status": "ok",
		"time":   time.Now().UTC(),
	})
}

func (h *Handler) Ready(w http.ResponseWriter, r *http.Request) {
	if !h.ready.Load() {
		response.Error(w, http.StatusServiceUnavailable, "service_unavailable", "service unavailable")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	err := h.db.Ping(ctx)

	if err != nil {
		response.Error(w, http.StatusServiceUnavailable, "service_unavailable", "database unavailable")
		return
	}

	response.Success(w, http.StatusOK, "service ready", nil)
}

func (h *Handler) Live(w http.ResponseWriter, r *http.Request) {
	response.Success(w, http.StatusOK, "service alive", nil)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.Health(w, r)
	case http.MethodHead:
		h.Ready(w, r)
	case http.MethodOptions:
		h.Live(w, r)
	default:
		response.HandleError(w, apperrors.ErrMethodNotAllowed)
	}
}
