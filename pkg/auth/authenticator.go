package auth

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/zijiren233/rauth/pkg/k8s"
)

// Authenticator handles authentication and authorization for registry requests
type Authenticator struct {
	k8sClient k8s.ClientInterface
	generator *TokenGenerator
	logger    *slog.Logger
}

// NewAuthenticator creates a new authenticator
func NewAuthenticator(k8sClient k8s.ClientInterface, generator *TokenGenerator, logger *slog.Logger) *Authenticator {
	return &Authenticator{
		k8sClient: k8sClient,
		generator: generator,
		logger:    logger,
	}
}

// AuthRequest represents an authentication request
type AuthRequest struct {
	Username string
	Password string
	Service  string
	Scope    string
	ClientID string
}

// AuthResult represents the result of authentication
type AuthResult struct {
	Authenticated bool     // true if credentials are valid
	Subject       string   // username/namespace
	Access        []Access // granted access (empty if no scope or unauthorized)
	Error         error    // error if authentication or authorization failed
}

// Authenticate authenticates and authorizes a registry request
// Flow: 1. Authenticate (verify credentials) → 2. Authorize (check scope access)
func (a *Authenticator) Authenticate(ctx context.Context, req *AuthRequest) *AuthResult {
	result := &AuthResult{}

	// ===========================================
	// Step 1: Authentication (verify credentials)
	// ===========================================
	// Username equals namespace, so we use username to get credentials
	creds, err := a.k8sClient.GetNamespaceCredentials(ctx, req.Username)
	if err != nil {
		a.logger.Warn("authentication failed: namespace not found",
			"username", req.Username,
			"error", err)
		result.Error = fmt.Errorf("authentication failed: invalid credentials")
		return result
	}

	if !a.verifyCredentials(req.Username, req.Password, creds) {
		a.logger.Warn("authentication failed: invalid password",
			"username", req.Username)
		result.Error = fmt.Errorf("authentication failed: invalid credentials")
		return result
	}

	result.Authenticated = true
	result.Subject = req.Username

	a.logger.Info("authentication successful", "username", req.Username)

	// ===========================================
	// Step 2: Authorization (check scope access)
	// ===========================================
	// If no scope, return empty access (e.g., docker login)
	if req.Scope == "" {
		a.logger.Info("no scope requested, returning empty access")
		result.Access = []Access{}
		return result
	}

	// Parse scope
	access, err := ParseScope(req.Scope)
	if err != nil {
		a.logger.Warn("failed to parse scope",
			"scope", req.Scope,
			"error", err)
		result.Error = fmt.Errorf("invalid scope: %w", err)
		return result
	}

	// Validate scope type is repository
	if access.Type != "repository" {
		a.logger.Warn("unsupported scope type",
			"type", access.Type)
		result.Error = fmt.Errorf("unsupported scope type: %s", access.Type)
		return result
	}

	// Authorize: check if user can access the requested repository
	if !a.authorizeAccess(req.Username, access) {
		a.logger.Warn("authorization denied",
			"username", req.Username,
			"repository", access.Name)
		result.Error = fmt.Errorf("access denied: unauthorized for repository %s", access.Name)
		return result
	}

	result.Access = []Access{*access}
	a.logger.Info("authorization successful",
		"username", req.Username,
		"repository", access.Name,
		"actions", access.Actions)

	return result
}

// verifyCredentials verifies username and password against stored credentials
func (a *Authenticator) verifyCredentials(username, password string, creds *k8s.RegistryCredentials) bool {
	// Use constant-time comparison to prevent timing attacks
	usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(creds.Username)) == 1
	passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(creds.Password)) == 1
	return usernameMatch && passwordMatch
}

// authorizeAccess checks if user can access the requested repository
// username == namespace, so user can only access repos in their own namespace
func (a *Authenticator) authorizeAccess(username string, requested *Access) bool {
	// Extract namespace from repository name (format: namespace/image)
	repoParts := strings.SplitN(requested.Name, "/", 2)
	if len(repoParts) < 2 {
		a.logger.Warn("invalid repository name format", "name", requested.Name)
		return false
	}

	// User can only access repositories in their own namespace
	return repoParts[0] == username
}

// GenerateToken generates a token for the authenticated user
func (a *Authenticator) GenerateToken(result *AuthResult) (*TokenResponse, error) {
	if !result.Authenticated {
		return nil, fmt.Errorf("user not authenticated")
	}

	token, err := a.generator.GenerateToken(result.Subject, result.Access)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	return &TokenResponse{
		Token:       token,
		AccessToken: token,
		ExpiresIn:   300, // 5 minutes
		IssuedAt:    time.Now().UTC().Format(time.RFC3339),
	}, nil
}
