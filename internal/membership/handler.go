package membership

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/requestctx"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/response"
	"github.com/mcchukwu/multi-tenant-authorization-service/internal/validation"
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
	members, err := h.service.ListMembers(r.Context(), orgID)
	if err != nil {
		response.HandleError(w, err)
		return
	}
	response.Success(w, http.StatusOK, "members retrieved", members)
}

func (h *Handler) Invite(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(r.PathValue("org_id"))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_org_id", "Invalid organization ID")
		return
	}
	inviterID, ok := requestctx.UserID(r.Context())
	if !ok {
		response.Error(w, http.StatusUnauthorized, "missing_identity", "Authentication required")
		return
	}

	var req InviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	if err := validation.ValidateStruct(req); err != nil {
		response.ValidationError(w, err)
		return
	}
	roleID, err := uuid.Parse(req.RoleID)
	if err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_role_id", "Invalid role ID")
		return
	}

	result, err := h.service.Invite(r.Context(), orgID, inviterID, roleID)
	if err != nil {
		response.HandleError(w, err)
		return
	}
	response.Success(w, http.StatusCreated, "invitation created", InviteResponse{
		Token:     result.Token,
		RoleID:    req.RoleID,
		ExpiresAt: result.ExpiresAt,
	})
}

// Accept is deliberately not org-scoped, {org_id} isn't known until the
// invitation itself resolves it, so this route carries no {org_id}
// segment and runs behind Authn only, never Authz.
func (h *Handler) Accept(w http.ResponseWriter, r *http.Request) {
	userID, ok := requestctx.UserID(r.Context())
	if !ok {
		response.Error(w, http.StatusUnauthorized, "missing_identity", "Authentication required")
		return
	}
	token := r.PathValue("token")
	if token == "" {
		response.Error(w, http.StatusBadRequest, "invalid_token", "Invitation token is required")
		return
	}

	orgID, err := h.service.Accept(r.Context(), userID, token)
	if err != nil {
		response.HandleError(w, err)
		return
	}
	response.Success(w, http.StatusOK, "invitation accepted", map[string]string{
		"organization_id": orgID.String(),
	})
}

// RotateInvite requires the invitation's ID in the route and uses the
// same member.invite permission as creating a fresh invite, rotating is
// conceptually "issue a new invite that replaces this one," not a
// separate capability.
func (h *Handler) RotateInvite(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(r.PathValue("org_id"))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_org_id", "Invalid organization ID")
		return
	}
	invitationID, err := uuid.Parse(r.PathValue("invitation_id"))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_invitation_id", "Invalid invitation ID")
		return
	}
	actorID, ok := requestctx.UserID(r.Context())
	if !ok {
		response.Error(w, http.StatusUnauthorized, "missing_identity", "Authentication required")
		return
	}

	result, err := h.service.RotateInvite(r.Context(), orgID, actorID, invitationID)
	if err != nil {
		response.HandleError(w, err)
		return
	}
	response.Success(w, http.StatusOK, "invitation rotated", InviteResponse{
		Token:     result.Token,
		ExpiresAt: result.ExpiresAt,
	})
}

// Leave has no Authz check any active member, any role, can leave.
// The service layer's own membership lookup is what naturally rejects
// someone who isn't a member of this org at all (ErrNotFound), so there's
// no meaningful permission to gate here beyond "you are who you are."
func (h *Handler) Leave(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(r.PathValue("org_id"))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_org_id", "Invalid organization ID")
		return
	}
	userID, ok := requestctx.UserID(r.Context())
	if !ok {
		response.Error(w, http.StatusUnauthorized, "missing_identity", "Authentication required")
		return
	}
	if err := h.service.Leave(r.Context(), orgID, userID); err != nil {
		response.HandleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) Remove(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(r.PathValue("org_id"))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_org_id", "Invalid organization ID")
		return
	}
	targetUserID, err := uuid.Parse(r.PathValue("user_id"))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_user_id", "Invalid user ID")
		return
	}
	actorID, ok := requestctx.UserID(r.Context())
	if !ok {
		response.Error(w, http.StatusUnauthorized, "missing_identity", "Authentication required")
		return
	}
	if err := h.service.Remove(r.Context(), orgID, actorID, targetUserID); err != nil {
		response.HandleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) AssignRole(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(r.PathValue("org_id"))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_org_id", "Invalid organization ID")
		return
	}
	targetUserID, err := uuid.Parse(r.PathValue("user_id"))
	if err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_user_id", "Invalid user ID")
		return
	}
	actorID, ok := requestctx.UserID(r.Context())
	if !ok {
		response.Error(w, http.StatusUnauthorized, "missing_identity", "Authentication required")
		return
	}

	var req AssignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	if err := validation.ValidateStruct(req); err != nil {
		response.ValidationError(w, err)
		return
	}
	newRoleID, err := uuid.Parse(req.RoleID)
	if err != nil {
		response.Error(w, http.StatusBadRequest, "invalid_role_id", "Invalid role ID")
		return
	}

	if err := h.service.AssignRole(r.Context(), orgID, actorID, targetUserID, newRoleID); err != nil {
		response.HandleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
