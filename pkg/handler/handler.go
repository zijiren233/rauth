package handler

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/zijiren233/rauth/pkg/auth"
)

// Handler handles HTTP requests for registry authentication
type Handler struct {
	authenticator *auth.Authenticator
	logger        *slog.Logger
}

// NewHandler creates a new HTTP handler
func NewHandler(authenticator *auth.Authenticator, logger *slog.Logger) *Handler {
	return &Handler{
		authenticator: authenticator,
		logger:        logger,
	}
}

// TokenHandler handles token requests from Docker Registry
// GET /token?service=xxx&scope=repository:namespace/image:pull
func (h *Handler) TokenHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract Basic Auth credentials
	username, password, ok := h.extractBasicAuth(r)
	if !ok {
		h.logger.Warn("missing or invalid authorization header")
		h.unauthorizedResponse(w, "missing credentials")
		return
	}

	// Parse query parameters
	service := r.URL.Query().Get("service")
	scope := r.URL.Query().Get("scope")
	clientID := r.URL.Query().Get("client_id")

	h.logger.Info("token request received",
		"service", service,
		"scope", scope,
		"username", username)

	// Create auth request
	authReq := &auth.AuthRequest{
		Username: username,
		Password: password,
		Service:  service,
		Scope:    scope,
		ClientID: clientID,
	}

	// Authenticate
	result := h.authenticator.Authenticate(ctx, authReq)
	if result.Error != nil || !result.Authenticated {
		h.logger.Warn("authentication failed",
			"username", username,
			"error", result.Error)
		h.unauthorizedResponse(w, "authentication failed")

		return
	}

	// Generate token
	tokenResp, err := h.authenticator.GenerateToken(result)
	if err != nil {
		h.logger.Error("failed to generate token", "error", err)
		h.internalErrorResponse(w, "failed to generate token")
		return
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tokenResp)
}

// HealthHandler handles health check requests
func (h *Handler) HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

// extractBasicAuth extracts username and password from Basic Auth header
func (h *Handler) extractBasicAuth(r *http.Request) (username, password string, ok bool) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", "", false
	}

	// Handle Basic Auth
	if !strings.HasPrefix(authHeader, "Basic ") {
		return "", "", false
	}

	encoded := strings.TrimPrefix(authHeader, "Basic ")

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", false
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	return parts[0], parts[1], true
}

// unauthorizedResponse sends a 401 Unauthorized response
func (h *Handler) unauthorizedResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Basic realm="Registry Authentication"`)
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             "unauthorized",
		"error_description": message,
	})
}

// internalErrorResponse sends a 500 Internal Server Error response
func (h *Handler) internalErrorResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             "internal_error",
		"error_description": message,
	})
}
