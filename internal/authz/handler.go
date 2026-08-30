package authz

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/response"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/utils"
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
	limit, offset := utils.ParsePagination(r)
	decisions, err := h.service.ListForOrg(r.Context(), orgID, limit, offset)
	if err != nil {
		response.HandleError(w, err)
		return
	}
	response.Success(w, http.StatusOK, "authorization decisions retrieved", decisions)
}
