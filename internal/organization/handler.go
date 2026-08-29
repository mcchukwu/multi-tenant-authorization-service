package organization

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/requestctx"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/response"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/validation"
)

type CreateOrgRequest struct {
	Name string `json:"name" validate:"required"`
}

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// Create is Authn-only, never wrapped in Authz — there's no {org_id} to
// scope against yet, since the whole point of this route is to make one.
// Any authenticated user can create a business org; type is never read
// from the request (see Service.Create).
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	userID, ok := requestctx.UserID(r.Context())
	if !ok {
		response.Error(w, http.StatusUnauthorized, "missing_identity", "Authentication required")
		return
	}

	var req CreateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	if err := validation.ValidateStruct(req); err != nil {
		response.ValidationError(w, err)
		return
	}

	org, err := h.service.Create(r.Context(), userID, req.Name)
	if err != nil {
		response.HandleError(w, err)
		return
	}
	response.Success(w, http.StatusCreated, "organization created", org)
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(r.PathValue("org_id"))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_org_id", "Invalid organization ID")
		return
	}
	org, err := h.service.Get(r.Context(), orgID)
	if err != nil {
		response.HandleError(w, err)
		return
	}
	response.Success(w, http.StatusOK, "organization retrieved", org)
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(r.PathValue("org_id"))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_org_id", "Invalid organization ID")
		return
	}

	var req UpdateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	if err := validation.ValidateStruct(req); err != nil {
		response.ValidationError(w, err)
		return
	}

	org, err := h.service.UpdateName(r.Context(), orgID, req.Name)
	if err != nil {
		response.HandleError(w, err)
		return
	}
	response.Success(w, http.StatusOK, "organization updated", org)
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(r.PathValue("org_id"))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_org_id", "Invalid organization ID")
		return
	}
	if err := h.service.Delete(r.Context(), orgID); err != nil {
		response.HandleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
