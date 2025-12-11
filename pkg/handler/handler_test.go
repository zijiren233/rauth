package handler_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/zijiren233/rauth/pkg/auth"
	"github.com/zijiren233/rauth/pkg/handler"
	"github.com/zijiren233/rauth/pkg/k8s"
)

// mockK8sClient implements k8s.ClientInterface for testing
type mockK8sClient struct {
	clientset  *fake.Clientset
	secretName string
}

func newMockK8sClient(secretName string, secrets ...*corev1.Secret) *mockK8sClient {
	var fakeClientset *fake.Clientset
	if len(secrets) == 0 {
		fakeClientset = fake.NewSimpleClientset()
	} else {
		fakeClientset = fake.NewSimpleClientset(secrets[0])
		for i := 1; i < len(secrets); i++ {
			fakeClientset.CoreV1().Secrets(secrets[i].Namespace).Create(
				context.Background(),
				secrets[i],
				metav1.CreateOptions{},
			)
		}
	}

	if secretName == "" {
		secretName = k8s.DefaultSecretName
	}

	return &mockK8sClient{
		clientset:  fakeClientset,
		secretName: secretName,
	}
}

func (c *mockK8sClient) GetNamespaceCredentials(ctx context.Context, namespace string) (*k8s.RegistryCredentials, error) {
	secret, err := c.clientset.CoreV1().Secrets(namespace).Get(ctx, c.secretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return k8s.ExtractCredentials(secret)
}

func (c *mockK8sClient) NamespaceExists(ctx context.Context, namespace string) (bool, error) {
	_, err := c.clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	return err == nil, nil
}

// setupTestHandler creates a test handler with mock k8s client
func setupTestHandler(t *testing.T, secrets ...*corev1.Secret) *handler.Handler {
	k8sClient := newMockK8sClient("", secrets...)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	generator, err := auth.NewTokenGenerator(&auth.TokenOption{
		Issuer:     "test-issuer",
		Service:    "test-service",
		Expiration: 5 * time.Minute,
		PrivateKey: privateKey,
	})
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	authenticator := auth.NewAuthenticator(k8sClient, generator, logger)
	return handler.NewHandler(authenticator, logger)
}

// basicAuth creates a Basic Auth header value
func basicAuth(username, password string) string {
	credentials := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))
}

// createTestSecret creates a test secret for a namespace
func createTestSecret(namespace, username, password string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      k8s.DefaultSecretName,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"username": []byte(username),
			"password": []byte(password),
		},
	}
}

// TestTokenHandler_Success tests successful token request
func TestTokenHandler_Success(t *testing.T) {
	secret := createTestSecret("team-a", "team-a", "secret-password")
	h := setupTestHandler(t, secret)

	req := httptest.NewRequest(http.MethodGet, "/token?service=registry&scope=repository:team-a/myapp:pull", nil)
	req.Header.Set("Authorization", basicAuth("team-a", "secret-password"))

	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotEmpty(t, response["token"])
	assert.NotEmpty(t, response["access_token"])
	assert.Equal(t, float64(300), response["expires_in"])
}

// TestTokenHandler_InvalidCredentials tests token request with wrong credentials
func TestTokenHandler_InvalidCredentials(t *testing.T) {
	secret := createTestSecret("team-a", "team-a", "correct-password")
	h := setupTestHandler(t, secret)

	req := httptest.NewRequest(http.MethodGet, "/token?service=registry&scope=repository:team-a/myapp:pull", nil)
	req.Header.Set("Authorization", basicAuth("team-a", "wrong-password"))

	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), "Basic")

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "unauthorized", response["error"])
}

// TestTokenHandler_MissingAuth tests token request without authorization header
func TestTokenHandler_MissingAuth(t *testing.T) {
	secret := createTestSecret("team-a", "team-a", "secret-password")
	h := setupTestHandler(t, secret)

	req := httptest.NewRequest(http.MethodGet, "/token?service=registry&scope=repository:team-a/myapp:pull", nil)
	// No Authorization header

	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestTokenHandler_InvalidAuthHeader tests various invalid auth header formats
func TestTokenHandler_InvalidAuthHeader(t *testing.T) {
	secret := createTestSecret("team-a", "team-a", "secret-password")
	h := setupTestHandler(t, secret)

	tests := []struct {
		name       string
		authHeader string
	}{
		{
			name:       "empty auth header",
			authHeader: "",
		},
		{
			name:       "bearer token instead of basic",
			authHeader: "Bearer some-token",
		},
		{
			name:       "invalid basic auth format",
			authHeader: "Basic invalid-not-base64!!!",
		},
		{
			name:       "basic without credentials",
			authHeader: "Basic",
		},
		{
			name:       "basic with only username (no colon)",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("usernameonly")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/token?service=registry&scope=repository:team-a/myapp:pull", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rr := httptest.NewRecorder()
			h.TokenHandler(rr, req)

			assert.Equal(t, http.StatusUnauthorized, rr.Code)
		})
	}
}

// TestTokenHandler_NamespaceNotFound tests request for non-existent namespace
func TestTokenHandler_NamespaceNotFound(t *testing.T) {
	// No secrets created
	h := setupTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/token?service=registry&scope=repository:nonexistent/myapp:pull", nil)
	req.Header.Set("Authorization", basicAuth("user", "pass"))

	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestTokenHandler_CrossNamespaceAccess tests accessing another namespace's images
func TestTokenHandler_CrossNamespaceAccess(t *testing.T) {
	secretA := createTestSecret("team-a", "team-a", "password-a")
	secretB := createTestSecret("team-b", "team-b", "password-b")
	h := setupTestHandler(t, secretA, secretB)

	// Team-A trying to access Team-B's image
	req := httptest.NewRequest(http.MethodGet, "/token?service=registry&scope=repository:team-b/myapp:pull", nil)
	req.Header.Set("Authorization", basicAuth("team-a", "password-a"))

	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)

	// Should fail - credentials don't match the target namespace
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestTokenHandler_EmptyScope tests request with no scope
func TestTokenHandler_EmptyScope(t *testing.T) {
	secret := createTestSecret("team-a", "team-a", "secret-password")
	h := setupTestHandler(t, secret)

	req := httptest.NewRequest(http.MethodGet, "/token?service=registry", nil)
	req.Header.Set("Authorization", basicAuth("team-a", "secret-password"))

	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)

	// Empty scope should succeed (for catalog access, etc.)
	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.NotEmpty(t, response["token"])
}

// TestTokenHandler_MultipleActions tests pull and push access
func TestTokenHandler_MultipleActions(t *testing.T) {
	secret := createTestSecret("team-a", "team-a", "secret-password")
	h := setupTestHandler(t, secret)

	req := httptest.NewRequest(http.MethodGet, "/token?service=registry&scope=repository:team-a/myapp:pull,push", nil)
	req.Header.Set("Authorization", basicAuth("team-a", "secret-password"))

	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.NotEmpty(t, response["token"])
}

// TestHealthHandler tests the health check endpoint
func TestHealthHandler(t *testing.T) {
	h := setupTestHandler(t)

	tests := []struct {
		name   string
		path   string
		method string
	}{
		{
			name:   "GET /health",
			path:   "/health",
			method: http.MethodGet,
		},
		{
			name:   "GET /healthz",
			path:   "/healthz",
			method: http.MethodGet,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rr := httptest.NewRecorder()

			h.HealthHandler(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

			var response map[string]interface{}
			err := json.Unmarshal(rr.Body.Bytes(), &response)
			require.NoError(t, err)
			assert.Equal(t, "healthy", response["status"])
		})
	}
}

// TestTokenHandler_SpecialCharactersInCredentials tests credentials with special chars
func TestTokenHandler_SpecialCharactersInCredentials(t *testing.T) {
	specialPassword := "p@ss!w0rd#$%^&*()"
	secret := createTestSecret("team-a", "team-a", specialPassword)
	h := setupTestHandler(t, secret)

	req := httptest.NewRequest(http.MethodGet, "/token?service=registry&scope=repository:team-a/myapp:pull", nil)
	req.Header.Set("Authorization", basicAuth("team-a", specialPassword))

	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestTokenHandler_UnicodeInCredentials tests credentials with unicode characters
func TestTokenHandler_UnicodeInCredentials(t *testing.T) {
	secret := createTestSecret("team-a", "用户", "密码")
	h := setupTestHandler(t, secret)

	req := httptest.NewRequest(http.MethodGet, "/token?service=registry&scope=repository:team-a/myapp:pull", nil)
	req.Header.Set("Authorization", basicAuth("用户", "密码"))

	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestTokenHandler_NestedImagePath tests nested image paths
func TestTokenHandler_NestedImagePath(t *testing.T) {
	secret := createTestSecret("team-a", "team-a", "secret-password")
	h := setupTestHandler(t, secret)

	req := httptest.NewRequest(http.MethodGet, "/token?service=registry&scope=repository:team-a/sub/path/myapp:pull", nil)
	req.Header.Set("Authorization", basicAuth("team-a", "secret-password"))

	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestTokenHandler_InvalidScopeFormat tests invalid scope format
func TestTokenHandler_InvalidScopeFormat(t *testing.T) {
	secret := createTestSecret("team-a", "team-a", "secret-password")
	h := setupTestHandler(t, secret)

	tests := []struct {
		name  string
		scope string
	}{
		{
			name:  "missing action",
			scope: "repository:team-a/myapp",
		},
		{
			name:  "no namespace in repository",
			scope: "repository:myapp:pull",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/token?service=registry&scope="+tt.scope, nil)
			req.Header.Set("Authorization", basicAuth("team-a", "secret-password"))

			rr := httptest.NewRecorder()
			h.TokenHandler(rr, req)

			assert.Equal(t, http.StatusUnauthorized, rr.Code)
		})
	}
}

// TestTokenHandler_ResponseHeaders tests response headers
func TestTokenHandler_ResponseHeaders(t *testing.T) {
	secret := createTestSecret("team-a", "team-a", "secret-password")
	h := setupTestHandler(t, secret)

	req := httptest.NewRequest(http.MethodGet, "/token?service=registry&scope=repository:team-a/myapp:pull", nil)
	req.Header.Set("Authorization", basicAuth("team-a", "secret-password"))

	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
}

// TestTokenHandler_UnauthorizedResponseHeaders tests WWW-Authenticate header
func TestTokenHandler_UnauthorizedResponseHeaders(t *testing.T) {
	secret := createTestSecret("team-a", "team-a", "secret-password")
	h := setupTestHandler(t, secret)

	req := httptest.NewRequest(http.MethodGet, "/token?service=registry&scope=repository:team-a/myapp:pull", nil)
	req.Header.Set("Authorization", basicAuth("team-a", "wrong-password"))

	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), "Basic")
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), "realm")
}

// TestTokenHandler_BasicAuthParsing tests Basic Auth parsing through the handler
func TestTokenHandler_BasicAuthParsing(t *testing.T) {
	secret := createTestSecret("team-a", "team-a", "secret-password")
	h := setupTestHandler(t, secret)

	tests := []struct {
		name         string
		authHeader   string
		wantStatus   int
	}{
		{
			name:       "valid basic auth",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("team-a:secret-password")),
			wantStatus: http.StatusOK,
		},
		{
			name:       "empty auth header",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "bearer instead of basic",
			authHeader: "Bearer token",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid base64",
			authHeader: "Basic not-valid-base64!!!",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "no colon in decoded",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("useronly")),
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/token?service=registry&scope=repository:team-a/myapp:pull", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rr := httptest.NewRecorder()
			h.TokenHandler(rr, req)

			assert.Equal(t, tt.wantStatus, rr.Code)
		})
	}
}

// TestTokenHandler_PasswordWithColon tests password containing colons
func TestTokenHandler_PasswordWithColon(t *testing.T) {
	secret := createTestSecret("team-a", "team-a", "pass:with:colons")
	h := setupTestHandler(t, secret)

	req := httptest.NewRequest(http.MethodGet, "/token?service=registry&scope=repository:team-a/myapp:pull", nil)
	req.Header.Set("Authorization", basicAuth("team-a", "pass:with:colons"))

	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestTokenHandler_EmptyPassword tests empty password
func TestTokenHandler_EmptyPassword(t *testing.T) {
	secret := createTestSecret("team-a", "team-a", "")
	h := setupTestHandler(t, secret)

	req := httptest.NewRequest(http.MethodGet, "/token?service=registry&scope=repository:team-a/myapp:pull", nil)
	req.Header.Set("Authorization", basicAuth("team-a", ""))

	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestHandler_ConcurrentRequests tests concurrent request handling
func TestHandler_ConcurrentRequests(t *testing.T) {
	secrets := []*corev1.Secret{
		createTestSecret("team-a", "team-a", "pass-a"),
		createTestSecret("team-b", "team-b", "pass-b"),
		createTestSecret("team-c", "team-c", "pass-c"),
	}
	h := setupTestHandler(t, secrets...)

	// Run concurrent requests
	done := make(chan bool, 30)

	for i := 0; i < 10; i++ {
		// Team A requests
		go func() {
			req := httptest.NewRequest(http.MethodGet, "/token?service=registry&scope=repository:team-a/app:pull", nil)
			req.Header.Set("Authorization", basicAuth("team-a", "pass-a"))
			rr := httptest.NewRecorder()
			h.TokenHandler(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code)
			done <- true
		}()

		// Team B requests
		go func() {
			req := httptest.NewRequest(http.MethodGet, "/token?service=registry&scope=repository:team-b/app:pull", nil)
			req.Header.Set("Authorization", basicAuth("team-b", "pass-b"))
			rr := httptest.NewRecorder()
			h.TokenHandler(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code)
			done <- true
		}()

		// Team C requests
		go func() {
			req := httptest.NewRequest(http.MethodGet, "/token?service=registry&scope=repository:team-c/app:pull", nil)
			req.Header.Set("Authorization", basicAuth("team-c", "pass-c"))
			rr := httptest.NewRecorder()
			h.TokenHandler(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 30; i++ {
		<-done
	}
}

// TestHandler_HTTPMethods tests that handler responds to different HTTP methods
func TestHandler_HTTPMethods(t *testing.T) {
	secret := createTestSecret("team-a", "team-a", "secret-password")
	h := setupTestHandler(t, secret)

	methods := []string{
		http.MethodGet,
		http.MethodPost, // Some clients might POST
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/token?service=registry&scope=repository:team-a/myapp:pull", nil)
			req.Header.Set("Authorization", basicAuth("team-a", "secret-password"))

			rr := httptest.NewRecorder()
			h.TokenHandler(rr, req)

			// Both GET and POST should work for token endpoint
			assert.Equal(t, http.StatusOK, rr.Code)
		})
	}
}

// TestTokenHandler_QueryParameters tests various query parameter combinations
func TestTokenHandler_QueryParameters(t *testing.T) {
	secret := createTestSecret("team-a", "team-a", "secret-password")
	h := setupTestHandler(t, secret)

	tests := []struct {
		name       string
		query      string
		wantStatus int
	}{
		{
			name:       "all parameters",
			query:      "service=registry&scope=repository:team-a/app:pull&client_id=docker",
			wantStatus: http.StatusOK,
		},
		{
			name:       "only service",
			query:      "service=registry",
			wantStatus: http.StatusOK,
		},
		{
			name:       "service and scope",
			query:      "service=registry&scope=repository:team-a/app:pull",
			wantStatus: http.StatusOK,
		},
		{
			name:       "empty service",
			query:      "service=&scope=repository:team-a/app:pull",
			wantStatus: http.StatusOK,
		},
		{
			name:       "no parameters",
			query:      "",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/token"
			if tt.query != "" {
				url += "?" + tt.query
			}

			req := httptest.NewRequest(http.MethodGet, url, nil)
			req.Header.Set("Authorization", basicAuth("team-a", "secret-password"))

			rr := httptest.NewRecorder()
			h.TokenHandler(rr, req)

			assert.Equal(t, tt.wantStatus, rr.Code)
		})
	}
}

// TestTokenHandler_TokenResponseStructure tests the structure of token response
func TestTokenHandler_TokenResponseStructure(t *testing.T) {
	secret := createTestSecret("team-a", "team-a", "secret-password")
	h := setupTestHandler(t, secret)

	req := httptest.NewRequest(http.MethodGet, "/token?service=registry&scope=repository:team-a/myapp:pull", nil)
	req.Header.Set("Authorization", basicAuth("team-a", "secret-password"))

	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)

	// Verify required fields exist
	assert.Contains(t, response, "token")
	assert.Contains(t, response, "access_token")
	assert.Contains(t, response, "expires_in")

	// token and access_token should be the same
	assert.Equal(t, response["token"], response["access_token"])

	// expires_in should be 300 (5 minutes)
	assert.Equal(t, float64(300), response["expires_in"])
}

// TestTokenHandler_ErrorResponseStructure tests the structure of error response
func TestTokenHandler_ErrorResponseStructure(t *testing.T) {
	h := setupTestHandler(t) // No secrets

	req := httptest.NewRequest(http.MethodGet, "/token?service=registry&scope=repository:team-a/myapp:pull", nil)
	req.Header.Set("Authorization", basicAuth("user", "pass"))

	rr := httptest.NewRecorder()
	h.TokenHandler(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)

	// Verify error response fields
	assert.Contains(t, response, "error")
	assert.Contains(t, response, "error_description")
	assert.Equal(t, "unauthorized", response["error"])
}
