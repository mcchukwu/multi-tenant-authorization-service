package role

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/response"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(r.PathValue("org_id"))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_org_id", "Invalid organization ID")
		return
	}
	roles, err := h.service.ListByOrg(r.Context(), orgID)
	if err != nil {
		response.HandleError(w, err)
		return
	}
	response.Success(w, http.StatusOK, "roles retrieved", roles)
}

